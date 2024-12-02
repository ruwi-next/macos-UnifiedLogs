// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

//! Parse macOS Unified Log data
//!
//! Provides a simple library to parse the macOS Unified Log format.

use std::borrow::Cow;

use crate::catalog::CatalogChunk;
use crate::chunks::firehose::activity::FirehoseActivity;
use crate::chunks::firehose::firehose_log::{Firehose, FirehoseItemInfo, FirehosePreamble};
use crate::chunks::firehose::nonactivity::FirehoseNonActivity;
use crate::chunks::firehose::signpost::FirehoseSignpost;
use crate::chunks::firehose::trace::FirehoseTrace;
use crate::chunks::oversize::Oversize;
use crate::chunks::simpledump::SimpleDump;
use crate::chunks::statedump::Statedump;
use crate::chunkset::ChunksetChunk;
use crate::dsc::SharedCacheStrings;
use crate::header::HeaderChunk;
use crate::message::format_firehose_log_message;
use crate::preamble::LogPreamble;
use crate::timesync::TimesyncBoot;
use log::{error, warn};
use nom::bytes::complete::take;
use serde::Serialize;

use crate::util::{extract_string, padding_size, unixepoch_to_iso};
use crate::uuidtext::UUIDText;

#[derive(Debug, Clone)]
pub struct UnifiedLogData<'a> {
    pub header: Vec<HeaderChunk>,
    pub catalog_data: Vec<UnifiedLogCatalogData<'a>>,
    pub oversize: Vec<Oversize<'a>>, // Keep a global cache of oversize string
}

#[derive(Debug, Clone)]
pub struct UnifiedLogCatalogData<'a> {
    pub catalog: CatalogChunk,
    pub firehose: Vec<FirehosePreamble>,
    pub simpledump: Vec<SimpleDump>,
    pub statedump: Vec<Statedump<'a>>,
    pub oversize: Vec<Oversize<'a>>,
}

#[derive(Debug)]
pub struct InternalLogData<'a> {
    pub subsystem: &'a str,
    pub thread_id: u64,
    pub pid: u64,
    pub euid: u32,
    pub library: &'a str,
    pub library_uuid: Cow<'a, str>,
    pub activity_id: u64,
    pub time: f64,
    pub category: Cow<'a, str>,
    pub event_type: EventType,
    pub log_type: LogType,
    pub process: &'a str,
    pub process_uuid: Cow<'a, str>,
    message_fmt: MessageFormatter<'a>,
    pub raw_message: &'a str,
    pub boot_uuid: &'a str,
    pub timezone_name: &'a str,
    pub message_entries: &'a [FirehoseItemInfo],
}

#[derive(Debug, Clone, Serialize)]
pub struct LogData {
    pub subsystem: String,
    pub thread_id: u64,
    pub pid: u64,
    pub euid: u32,
    pub library: String,
    pub library_uuid: String,
    pub activity_id: u64,
    pub time: f64,
    pub category: String,
    pub event_type: EventType,
    pub log_type: LogType,
    pub process: String,
    pub process_uuid: String,
    pub message: String,
    pub raw_message: String,
    pub boot_uuid: String,
    pub timezone_name: String,
    pub message_entries: Vec<FirehoseItemInfo>,
}

impl From<InternalLogData<'_>> for LogData {
    fn from(value: InternalLogData<'_>) -> Self {
        let message = value.message().into_owned();
        Self {
            message,
            subsystem: value.subsystem.to_owned(),
            thread_id: value.thread_id,
            pid: value.pid,
            euid: value.euid,
            library: value.library.to_owned(),
            library_uuid: value.library_uuid.into_owned(),
            activity_id: value.activity_id,
            time: value.time,
            category: value.category.into_owned(),
            event_type: value.event_type,
            log_type: value.log_type,
            process: value.process.to_owned(),
            process_uuid: value.process_uuid.into_owned(),
            raw_message: value.raw_message.to_owned(),
            boot_uuid: value.boot_uuid.to_owned(),
            timezone_name: value.timezone_name.to_owned(),
            message_entries: value.message_entries.to_owned(),
        }
    }
}

#[derive(Debug)]
enum MessageFormatter<'a> {
    Empty,
    Ref(&'a str),
    Backtrace {
        firehose: &'a Firehose,
        preamble: &'a FirehosePreamble,
        unified_log_data: &'a UnifiedLogData<'a>,
        format_string: &'a str,
    },
    Backtrace2 {
        backtrace: &'a [String],
        format_string: &'a str,
        item_message: &'a [FirehoseItemInfo],
    },
    BacktraceSignpost {
        firehose: &'a Firehose,
        preamble: &'a FirehosePreamble,
        unified_log_data: &'a UnifiedLogData<'a>,
        format_string: &'a str,
    },
    Catalog {
        title: &'a str,
        decoder_library: &'a str,
        decoder_type: &'a str,
        statedump: &'a Statedump<'a>,
    },
}

pub trait LogFilter {
    fn filter(&self, event_type: EventType, log_type: LogType) -> bool;
}

pub struct EverythingLogFilter;

impl LogFilter for EverythingLogFilter {
    fn filter(&self, _event_type: EventType, _log_type: LogType) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LogType {
    Debug,
    Info,
    Default,
    Error,
    Fault,
    Create,
    Useraction,
    ProcessSignpostEvent,
    ProcessSignpostStart,
    ProcessSignpostEnd,
    SystemSignpostEvent,
    SystemSignpostStart,
    SystemSignpostEnd,
    ThreadSignpostEvent,
    ThreadSignpostStart,
    ThreadSignpostEnd,
    Simpledump,
    Statedump,
    Loss,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EventType {
    Unknown,
    Log,
    Activity,
    Trace,
    Signpost,
    Simpledump,
    Statedump,
    Loss,
}

impl<'a> InternalLogData<'a> {
    /// Parse the Unified log data read from a tracev3 file
    pub fn parse_unified_log(data: &'a [u8]) -> nom::IResult<&'a [u8], UnifiedLogData<'a>> {
        let mut unified_log_data_true = UnifiedLogData {
            header: Vec::new(),
            catalog_data: Vec::new(),
            oversize: Vec::new(),
        };

        let mut catalog_data = UnifiedLogCatalogData {
            catalog: CatalogChunk {
                chunk_tag: 0,
                chunk_sub_tag: 0,
                chunk_data_size: 0,
                catalog_subsystem_strings_offset: 0,
                catalog_process_info_entries_offset: 0,
                number_process_information_entries: 0,
                catalog_offset_sub_chunks: 0,
                number_sub_chunks: 0,
                unknown: Vec::new(),
                earliest_firehose_timestamp: 0,
                catalog_uuids: Vec::new(),
                catalog_subsystem_strings: Vec::new(),
                catalog_process_info_entries: Vec::new(),
                catalog_subchunks: Vec::new(),
            },
            firehose: Vec::new(),
            simpledump: Vec::new(),
            statedump: Vec::new(),
            oversize: Vec::new(),
        };

        let mut input = data;
        let chunk_preamble_size = 16; // Include preamble size in total chunk size

        let header_chunk = 0x1000;
        let catalog_chunk = 0x600b;
        let chunkset_chunk = 0x600d;
        // Loop through traceV3 file until all file contents are read
        while !input.is_empty() {
            let (_, preamble) = LogPreamble::detect_preamble(input)?;
            let chunk_size = preamble.chunk_data_size;

            // Grab all data associated with Unified Log entry (chunk)
            let (data, chunk_data) = take(chunk_size + chunk_preamble_size)(input)?;

            if preamble.chunk_tag == header_chunk {
                InternalLogData::get_header_data(chunk_data, &mut unified_log_data_true);
            } else if preamble.chunk_tag == catalog_chunk {
                if catalog_data.catalog.chunk_tag != 0 {
                    unified_log_data_true.catalog_data.push(catalog_data);
                }
                catalog_data = UnifiedLogCatalogData {
                    catalog: CatalogChunk {
                        chunk_tag: 0,
                        chunk_sub_tag: 0,
                        chunk_data_size: 0,
                        catalog_subsystem_strings_offset: 0,
                        catalog_process_info_entries_offset: 0,
                        number_process_information_entries: 0,
                        catalog_offset_sub_chunks: 0,
                        number_sub_chunks: 0,
                        unknown: Vec::new(),
                        earliest_firehose_timestamp: 0,
                        catalog_uuids: Vec::new(),
                        catalog_subsystem_strings: Vec::new(),
                        catalog_process_info_entries: Vec::new(),
                        catalog_subchunks: Vec::new(),
                    },
                    firehose: Vec::new(),
                    simpledump: Vec::new(),
                    statedump: Vec::new(),
                    oversize: Vec::new(),
                };

                InternalLogData::get_catalog_data(chunk_data, &mut catalog_data);
            } else if preamble.chunk_tag == chunkset_chunk {
                InternalLogData::get_chunkset_data(
                    chunk_data,
                    &mut catalog_data,
                    &mut unified_log_data_true,
                );
            } else {
                error!(
                    "[macos-unifiedlogs] Unknown chunk type: {:?}",
                    preamble.chunk_tag
                );
            }

            let padding_size = padding_size(preamble.chunk_data_size);
            if data.len() < padding_size as usize {
                break;
            }
            let (data, _) = take(padding_size)(data)?;
            if data.is_empty() {
                break;
            }
            input = data;
            if input.len() < chunk_preamble_size as usize {
                warn!(
                    "Not enough data for preamble header, needed 16 bytes. Got: {:?}",
                    input.len()
                );
                break;
            }
        }
        // Make sure to get the last catalog
        if catalog_data.catalog.chunk_tag != 0 {
            unified_log_data_true.catalog_data.push(catalog_data);
        }
        Ok((input, unified_log_data_true))
    }

    /// Reconstruct Unified Log entries using the binary strings data, cached strings data, timesync data, and unified log. Provide bool to ignore log entries that are not able to be recontructed (additional tracev3 files needed)
    /// Return a reconstructed log entries and any leftover Unified Log entries that could not be reconstructed (data may be stored in other tracev3 files)
    pub fn build_log<F>(
        unified_log_data: &'a UnifiedLogData<'a>,
        strings_data: &'a [UUIDText],
        shared_strings: &'a [SharedCacheStrings],
        timesync_data: &'a [TimesyncBoot],
        log_filter: &'a F,
    ) -> impl Iterator<Item = InternalLogData<'a>> + 'a
    where
        F: LogFilter,
    {
        unified_log_data
            .catalog_data
            .iter()
            .flat_map(move |catalog_data| {
                Self::build_log_from_catalog(
                    catalog_data,
                    unified_log_data,
                    strings_data,
                    shared_strings,
                    timesync_data,
                    log_filter,
                )
            })
    }

    pub fn build_log_from_catalog<F>(
        catalog_data: &'a UnifiedLogCatalogData<'a>,
        unified_log_data: &'a UnifiedLogData<'a>,
        strings_data: &'a [UUIDText],
        shared_strings: &'a [SharedCacheStrings],
        timesync_data: &'a [TimesyncBoot],
        log_filter: &'a F,
    ) -> impl Iterator<Item = InternalLogData<'a>> + 'a
    where
        F: LogFilter,
    {
        catalog_data
            .firehose
            .iter()
            .flat_map(move |preamble| {
                preamble.public_data.iter().flat_map(move |firehose| {
                    convert_log(
                        firehose,
                        preamble,
                        timesync_data,
                        unified_log_data,
                        catalog_data,
                        strings_data,
                        shared_strings,
                        log_filter,
                    )
                })
            })
            .chain(catalog_data.simpledump.iter().flat_map(|simpledump| {
                let subsystem = simpledump.subsystem.as_str();
                if !log_filter.filter(EventType::Simpledump, LogType::Simpledump) {
                    return None;
                }
                let no_firehose_preamble = 1;

                let timestamp = TimesyncBoot::get_timestamp(
                    timesync_data,
                    &unified_log_data.header[0].boot_uuid,
                    simpledump.continous_time,
                    no_firehose_preamble,
                );
                Some(InternalLogData {
                    subsystem,
                    thread_id: simpledump.thread_id,
                    pid: simpledump.first_proc_id,
                    library: "",
                    activity_id: 0,
                    time: timestamp,
                    category: "".into(),
                    log_type: LogType::Simpledump,
                    process: "",
                    message_fmt: MessageFormatter::Ref(&simpledump.message_string),
                    event_type: EventType::Simpledump,
                    euid: 0,
                    boot_uuid: &unified_log_data.header[0].boot_uuid,
                    timezone_name: unified_log_data.header[0]
                        .timezone_path
                        .split('/')
                        .last()
                        .unwrap_or("Unknown Timezone Name"),
                    library_uuid: simpledump.sender_uuid.clone().into(),
                    process_uuid: simpledump.dsc_uuid.clone().into(),
                    raw_message: "",
                    message_entries: &[],
                })
            }))
            .chain(catalog_data.statedump.iter().flat_map(|statedump| {
                if !log_filter.filter(EventType::Statedump, LogType::Statedump) {
                    return None;
                }
                let no_firehose_preamble = 1;

                let timestamp = TimesyncBoot::get_timestamp(
                    timesync_data,
                    &unified_log_data.header[0].boot_uuid,
                    statedump.continuous_time,
                    no_firehose_preamble,
                );
                Some(InternalLogData {
                    subsystem: "",
                    thread_id: 0,
                    pid: statedump.first_proc_id,
                    library: "",
                    activity_id: statedump.activity_id,
                    time: timestamp,
                    category: "".into(),
                    event_type: EventType::Statedump,
                    process: "",
                    // "title: {:?}\nObject Type: {:?}\n Object Type: {:?}\n{:?}",
                    message_fmt: MessageFormatter::Catalog {
                        title: statedump.title_name,
                        decoder_library: statedump.decoder_library,
                        decoder_type: statedump.decoder_type,
                        statedump,
                    },
                    log_type: LogType::Statedump,
                    euid: 0,
                    boot_uuid: &unified_log_data.header[0].boot_uuid,
                    timezone_name: unified_log_data.header[0]
                        .timezone_path
                        .split('/')
                        .last()
                        .unwrap_or("Unknown Timezone Name"),
                    library_uuid: "".into(),
                    process_uuid: "".into(),
                    raw_message: "",
                    message_entries: &[],
                })
            }))
    }

    /// Return log type based on parsed log data
    fn get_log_type(log_type: u8, activity_type: u8) -> LogType {
        match log_type {
            0x1 => {
                let activity = 2;
                if activity_type == activity {
                    LogType::Create
                } else {
                    LogType::Info
                }
            }
            0x2 => LogType::Debug,
            0x3 => LogType::Useraction,
            0x10 => LogType::Error,
            0x11 => LogType::Fault,
            0x80 => LogType::ProcessSignpostEvent,
            0x81 => LogType::ProcessSignpostStart,
            0x82 => LogType::ProcessSignpostEnd,
            0xc0 => LogType::SystemSignpostEvent, // Not seen but may exist?
            0xc1 => LogType::SystemSignpostStart,
            0xc2 => LogType::SystemSignpostEnd,
            0x40 => LogType::ThreadSignpostEvent, // Not seen but may exist?
            0x41 => LogType::ThreadSignpostStart,
            0x42 => LogType::ThreadSignpostEnd,
            _ => LogType::Default,
        }
    }

    /// Return the log event type based on parsed log data
    fn get_event_type(event_type: u8) -> EventType {
        match event_type {
            0x4 => EventType::Log,
            0x2 => EventType::Activity,
            0x3 => EventType::Trace,
            0x6 => EventType::Signpost,
            0x7 => EventType::Loss,
            _ => EventType::Unknown,
        }
    }

    /// Get the header of the Unified Log data (tracev3 file)
    fn get_header_data(data: &[u8], unified_log_data: &mut UnifiedLogData<'a>) {
        let header_results = HeaderChunk::parse_header(data);
        match header_results {
            Ok((_, header_data)) => unified_log_data.header.push(header_data),
            Err(err) => error!("[macos-unifiedlogs] Failed to parse header data: {:?}", err),
        }
    }

    /// Get the Catalog of the Unified Log data (tracev3 file)
    fn get_catalog_data(data: &[u8], unified_log_data: &mut UnifiedLogCatalogData<'a>) {
        let catalog_results = CatalogChunk::parse_catalog(data);
        match catalog_results {
            Ok((_, catalog_data)) => unified_log_data.catalog = catalog_data,
            Err(err) => error!(
                "[macos-unifiedlogs] Failed to parse catalog data: {:?}",
                err
            ),
        }
    }

    /// Get the Chunkset of the Unified Log data (tracev3)
    fn get_chunkset_data<'e, 'c>(
        data: &'e [u8],
        catalog_data: &'c mut UnifiedLogCatalogData<'e>,
        unified_log_data: &'c mut UnifiedLogData<'e>,
    ) where
        'e: 'c,
    {
        // Parse and decompress the chunkset entries
        let chunkset_data_results = ChunksetChunk::parse_chunkset(data);
        match chunkset_data_results {
            Ok((_, chunkset_data)) => {
                // Parse the decompressed data which contains the log data
                // TODO: Fix leak
                let _result = ChunksetChunk::parse_chunkset_data(
                    chunkset_data.decompressed_data.leak(),
                    catalog_data,
                )
                .unwrap();
                unified_log_data.oversize.append(&mut catalog_data.oversize);
            }
            Err(err) => error!(
                "[macos-unifiedlogs] Failed to parse chunkset data: {:?}",
                err
            ),
        }
    }

    pub fn timestamp(&self) -> String {
        unixepoch_to_iso(&(self.time as i64))
    }

    pub fn message(&self) -> Cow<'_, str> {
        match &self.message_fmt {
            MessageFormatter::Empty => "".into(),
            MessageFormatter::Ref(s) => (*s).into(),
            MessageFormatter::Backtrace {
                firehose,
                preamble,
                unified_log_data,
                format_string,
            } => {
                let log_message = if firehose.firehose_non_activity.data_ref_value != 0 {
                    let oversize_strings = Oversize::get_oversize_strings(
                        firehose.firehose_non_activity.data_ref_value,
                        preamble.first_number_proc_id,
                        preamble.second_number_proc_id,
                        &unified_log_data.oversize,
                    );
                    // Format and map the log strings with the message format string found UUIDText or shared string file
                    format_firehose_log_message(format_string, &oversize_strings)
                } else {
                    // Format and map the log strings with the message format string found UUIDText or shared string file
                    format_firehose_log_message(format_string, &firehose.message.item_info)
                };

                let data = log_message;
                let backtrace = &firehose.message.backtrace_strings;

                if backtrace.is_empty() {
                    data.into()
                } else {
                    let backtrace = backtrace.join("\n");
                    format!("Backtrace:\n{backtrace}\n{data}").into()
                }
            }
            MessageFormatter::Backtrace2 {
                backtrace,
                format_string,
                item_message,
            } => {
                let data = format_firehose_log_message(format_string, item_message);
                if backtrace.is_empty() {
                    data.into()
                } else {
                    let backtrace = backtrace.join("\n");
                    format!("Backtrace:\n{backtrace}\n{data}").into()
                }
            }
            MessageFormatter::BacktraceSignpost {
                firehose,
                preamble,
                unified_log_data,
                format_string,
            } => {
                let log_message = if firehose.firehose_non_activity.data_ref_value != 0 {
                    let oversize_strings = Oversize::get_oversize_strings(
                        firehose.firehose_non_activity.data_ref_value,
                        preamble.first_number_proc_id,
                        preamble.second_number_proc_id,
                        &unified_log_data.oversize,
                    );
                    // Format and map the log strings with the message format string found UUIDText or shared string file
                    format_firehose_log_message(format_string, &oversize_strings)
                } else {
                    // Format and map the log strings with the message format string found UUIDText or shared string file
                    format_firehose_log_message(format_string, &firehose.message.item_info)
                };

                let log_message = format!(
                    "Signpost ID: {:X} - Signpost Name: {:X}\n {}",
                    firehose.firehose_signpost.signpost_id,
                    firehose.firehose_signpost.signpost_name,
                    log_message
                );

                let data = log_message;
                let backtrace = &firehose.message.backtrace_strings;

                if backtrace.is_empty() {
                    data.into()
                } else {
                    let backtrace = backtrace.join("\n");
                    format!("Backtrace:\n{backtrace}\n{data}").into()
                }
            }
            MessageFormatter::Catalog {
                title,
                decoder_library,
                decoder_type,
                statedump,
            } => {
                let data_string = match statedump.unknown_data_type {
                    0x1 => Statedump::parse_statedump_plist(statedump.statedump_data),
                    0x2 => "Statedump Protocol Buffer".into(),
                    0x3 => Statedump::parse_statedump_object(
                        statedump.statedump_data,
                        statedump.title_name,
                    )
                    .into(),
                    _ => {
                        warn!(
                            "Unknown statedump data type: {}",
                            statedump.unknown_data_type
                        );
                        let results = extract_string(statedump.statedump_data);
                        match results {
                            Ok((_, string_data)) => string_data.to_owned().into(),
                            Err(err) => {
                                error!("[macos-unifiedlogs] Failed to extract string from statedump: {:?}", err);
                                "Failed to extract string from statedump".into()
                            }
                        }
                    }
                };

                format!("title: {title:?}\nObject Type: {decoder_library:?}\n Object Type: {decoder_type:?}\n{data_string:?}").into()
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn convert_log<'a, F>(
    firehose: &'a Firehose,
    preamble: &'a FirehosePreamble,
    timesync_data: &[TimesyncBoot],
    unified_log_data: &'a UnifiedLogData<'a>,
    catalog_data: &'a UnifiedLogCatalogData<'a>,
    strings_data: &'a [UUIDText],
    shared_strings: &'a [SharedCacheStrings],
    log_filter: &'a F,
) -> Option<InternalLogData<'a>>
where
    F: LogFilter,
{
    let event_type = InternalLogData::get_event_type(firehose.unknown_log_activity_type);
    let log_type = InternalLogData::get_log_type(
        firehose.unknown_log_type,
        firehose.unknown_log_activity_type,
    );
    if !log_filter.filter(event_type, log_type) {
        return None;
    }

    // The continous time is actually 6 bytes long. Combining 4 bytes and 2 bytes
    let firehose_log_entry_continous_time = u64::from(firehose.continous_time_delta)
        | ((u64::from(firehose.continous_time_delta_upper)) << 32);

    let continous_time = preamble.base_continous_time + firehose_log_entry_continous_time;

    // Calculate the timestamp for the log entry
    let timestamp = TimesyncBoot::get_timestamp(
        timesync_data,
        &unified_log_data.header[0].boot_uuid,
        continous_time,
        preamble.base_continous_time,
    );

    // Our struct format to hold and show the log data
    let mut log_data = InternalLogData {
        subsystem: "",
        thread_id: firehose.thread_id,
        pid: CatalogChunk::get_pid(
            &preamble.first_number_proc_id,
            &preamble.second_number_proc_id,
            &catalog_data.catalog,
        ),
        library: "",
        activity_id: 0,
        time: timestamp,
        category: "".into(),
        log_type,
        process: "",
        message_fmt: MessageFormatter::Empty,
        event_type,
        euid: CatalogChunk::get_euid(
            &preamble.first_number_proc_id,
            &preamble.second_number_proc_id,
            &catalog_data.catalog,
        ),
        boot_uuid: &unified_log_data.header[0].boot_uuid,
        timezone_name: unified_log_data.header[0]
            .timezone_path
            .split('/')
            .last()
            .unwrap_or("Unknown Timezone Name"),
        library_uuid: "".into(),
        process_uuid: "".into(),
        raw_message: "",
        message_entries: &firehose.message.item_info,
    };

    // 0x4 - Non-activity log entry. Ex: log default, log error, etc
    // 0x2 - Activity log entry. Ex: activity create
    // 0x7 - Loss log entry. Ex: loss
    // 0x6 - Signpost entry. Ex: process signpost, thread signpost, system signpost
    // 0x3 - Trace log entry. Ex: trace default
    match firehose.unknown_log_activity_type {
        0x4 => {
            log_data.activity_id = u64::from(firehose.firehose_non_activity.unknown_activity_id);
            let message_data = FirehoseNonActivity::get_firehose_nonactivity_strings(
                &firehose.firehose_non_activity,
                strings_data,
                shared_strings,
                u64::from(firehose.format_string_location),
                preamble.first_number_proc_id,
                preamble.second_number_proc_id,
                &catalog_data.catalog,
            );

            match message_data {
                Ok((_, results)) => {
                    log_data.library = results.library;
                    log_data.library_uuid = results.library_uuid.into();
                    log_data.process = results.process;
                    log_data.process_uuid = results.process_uuid.into();
                    log_data.raw_message = results.format_string;

                    log_data.message_fmt = MessageFormatter::Backtrace {
                        firehose,
                        preamble,
                        unified_log_data,
                        format_string: results.format_string,
                    };
                }
                Err(err) => {
                    warn!("[macos-unifiedlogs] Failed to get message string data for firehose non-activity log entry: {:?}", err);
                }
            }

            if firehose.firehose_non_activity.subsystem_value != 0 {
                let results = CatalogChunk::get_subsystem(
                    &firehose.firehose_non_activity.subsystem_value,
                    preamble.first_number_proc_id,
                    preamble.second_number_proc_id,
                    &catalog_data.catalog,
                );
                match results {
                    Ok((_, subsystem)) => {
                        log_data.subsystem = subsystem.subsystem;
                        log_data.category = subsystem.category.into();
                    }
                    Err(err) => warn!("[macos-unifiedlogs] Failed to get subsystem: {:?}", err),
                }
            }
        }
        0x7 => {
            // No message data in loss entries
            log_data.event_type = EventType::Loss;
            log_data.log_type = LogType::Loss;
        }
        0x2 => {
            log_data.activity_id = u64::from(firehose.firehose_activity.unknown_activity_id);
            let message_data = FirehoseActivity::get_firehose_activity_strings(
                &firehose.firehose_activity,
                strings_data,
                shared_strings,
                u64::from(firehose.format_string_location),
                preamble.first_number_proc_id,
                preamble.second_number_proc_id,
                &catalog_data.catalog,
            );
            match message_data {
                Ok((_, results)) => {
                    log_data.library = results.library;
                    log_data.library_uuid = results.library_uuid.into();
                    log_data.process = results.process;
                    log_data.process_uuid = results.process_uuid.into();
                    log_data.raw_message = results.format_string;

                    log_data.message_fmt = MessageFormatter::Backtrace2 {
                        backtrace: &firehose.message.backtrace_strings,
                        format_string: results.format_string,
                        item_message: &firehose.message.item_info,
                    };
                }
                Err(err) => {
                    warn!("[macos-unifiedlogs] Failed to get message string data for firehose activity log entry: {:?}", err);
                }
            }
        }
        0x6 => {
            log_data.activity_id = u64::from(firehose.firehose_signpost.unknown_activity_id);
            let message_data = FirehoseSignpost::get_firehose_signpost(
                &firehose.firehose_signpost,
                strings_data,
                shared_strings,
                u64::from(firehose.format_string_location),
                preamble.first_number_proc_id,
                preamble.second_number_proc_id,
                &catalog_data.catalog,
            );
            match message_data {
                Ok((_, results)) => {
                    log_data.library = results.library;
                    log_data.library_uuid = results.library_uuid.into();
                    log_data.process = results.process;
                    log_data.process_uuid = results.process_uuid.into();
                    log_data.raw_message = results.format_string;

                    log_data.message_fmt = MessageFormatter::BacktraceSignpost {
                        firehose,
                        preamble,
                        unified_log_data,
                        format_string: results.format_string,
                    };
                }
                Err(err) => {
                    warn!("[macos-unifiedlogs] Failed to get message string data for firehose signpost log entry: {:?}", err);
                }
            }
            if firehose.firehose_signpost.subsystem != 0 {
                let results = CatalogChunk::get_subsystem(
                    &firehose.firehose_signpost.subsystem,
                    preamble.first_number_proc_id,
                    preamble.second_number_proc_id,
                    &catalog_data.catalog,
                );
                match results {
                    Ok((_, subsystem)) => {
                        log_data.subsystem = subsystem.subsystem;
                        log_data.category = subsystem.category.into();
                    }
                    Err(err) => warn!("[macos-unifiedlogs] Failed to get subsystem: {:?}", err),
                }
            }
        }
        0x3 => {
            let message_data = FirehoseTrace::get_firehose_trace_strings(
                strings_data,
                u64::from(firehose.format_string_location),
                preamble.first_number_proc_id,
                preamble.second_number_proc_id,
                &catalog_data.catalog,
            );
            match message_data {
                Ok((_, results)) => {
                    log_data.library = results.library;
                    log_data.library_uuid = results.library_uuid.into();
                    log_data.process = results.process;
                    log_data.process_uuid = results.process_uuid.into();

                    log_data.message_fmt = MessageFormatter::Backtrace2 {
                        backtrace: &firehose.message.backtrace_strings,
                        format_string: results.format_string,
                        item_message: &firehose.message.item_info,
                    };
                }
                Err(err) => {
                    warn!("[macos-unifiedlogs] Failed to get message string data for firehose activity log entry: {:?}", err);
                }
            }
        }
        _ => error!(
            "[macos-unifiedlogs] Parsed unknown log firehose data: {:?}",
            firehose
        ),
    }
    Some(log_data)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use crate::{
        catalog::CatalogChunk,
        parser::{
            buffer_from_path, collect_shared_strings, collect_strings, collect_timesync, parse_log,
        },
        unified_log::{EventType, EverythingLogFilter, LogType, UnifiedLogCatalogData},
    };

    use super::{InternalLogData, UnifiedLogData};

    #[test]
    fn test_parse_unified_log() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(
            "tests/test_data/system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3",
        );

        let buffer = fs::read(test_path).unwrap();

        let (_, results) = InternalLogData::parse_unified_log(&buffer).unwrap();
        assert_eq!(results.catalog_data.len(), 56);
        assert_eq!(results.header.len(), 1);
        assert_eq!(results.oversize.len(), 12);
    }

    #[test]
    fn test_bad_log_header() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Bad Data/TraceV3/Bad_header_0000000000000005.tracev3");

        let buffer = fs::read(test_path).unwrap();
        let (_, results) = InternalLogData::parse_unified_log(&buffer).unwrap();
        assert_eq!(results.catalog_data.len(), 36);
        assert_eq!(results.header.len(), 0);
        assert_eq!(results.oversize.len(), 28);
    }

    #[test]
    #[should_panic(expected = "Eof")]
    fn test_bad_log_content() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Bad Data/TraceV3/Bad_content_0000000000000005.tracev3");

        let buffer = fs::read(test_path).unwrap();
        let (_, _) = InternalLogData::parse_unified_log(&buffer).unwrap();
    }

    #[test]
    #[should_panic(expected = "Eof")]
    fn test_bad_log_file() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Bad Data/TraceV3/00.tracev3");

        let buffer = fs::read(test_path).unwrap();
        let (_, _) = InternalLogData::parse_unified_log(&buffer).unwrap();
    }

    #[test]
    fn test_build_log() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let string_results = collect_strings(&test_path).unwrap();

        test_path.push("dsc");
        let shared_strings_results = collect_shared_strings(&test_path).unwrap();
        test_path.pop();

        test_path.push("timesync");
        let timesync_data = collect_timesync(&test_path).unwrap();
        test_path.pop();

        test_path.push("Persist/0000000000000002.tracev3");

        let data = buffer_from_path(&test_path).unwrap();
        let log_data = parse_log(&data).unwrap();

        let results: Vec<_> = InternalLogData::build_log(
            &log_data,
            &string_results,
            &shared_strings_results,
            &timesync_data,
            &EverythingLogFilter,
        )
        .into_iter()
        .collect();
        assert_eq!(results.len(), 207366);
        assert_eq!(results[0].process, "/usr/libexec/lightsoutmanagementd");
        assert_eq!(results[0].subsystem, "com.apple.lom");
        assert_eq!(results[0].time, 1642302326434850732.0);
        assert_eq!(results[0].activity_id, 0);
        assert_eq!(results[0].library, "/usr/libexec/lightsoutmanagementd");
        assert_eq!(results[0].library_uuid, "6C3ADF991F033C1C96C4ADFAA12D8CED");
        assert_eq!(results[0].process_uuid, "6C3ADF991F033C1C96C4ADFAA12D8CED");
        assert_eq!(results[0].message(), "LOMD Start");
        assert_eq!(results[0].pid, 45);
        assert_eq!(results[0].thread_id, 588);
        assert_eq!(results[0].category, "device");
        assert_eq!(results[0].log_type, LogType::Default);
        assert_eq!(results[0].event_type, EventType::Log);
        assert_eq!(results[0].euid, 0);
        assert_eq!(results[0].boot_uuid, "80D194AF56A34C54867449D2130D41BB");
        assert_eq!(results[0].timezone_name, "Pacific");
        assert_eq!(results[0].raw_message, "LOMD Start");
        assert_eq!(results[0].timestamp(), "2022-01-16T03:05:26.434850816Z")
    }

    #[test]
    fn test_get_log_type() {
        let mut log_type = 0x2;
        let activity_type = 0x2;

        let mut log_string = InternalLogData::get_log_type(log_type, activity_type);
        assert_eq!(log_string, LogType::Debug);
        log_type = 0x1;
        log_string = InternalLogData::get_log_type(log_type, activity_type);
        assert_eq!(log_string, LogType::Create);
    }

    #[test]
    fn test_get_event_type() {
        let event_type = 0x2;
        let event_string = InternalLogData::get_event_type(event_type);
        assert_eq!(event_string, EventType::Activity);
    }

    #[test]
    fn test_get_header_data() {
        let test_chunk_header = [
            0, 16, 0, 0, 17, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 15, 105,
            217, 162, 204, 126, 0, 0, 48, 215, 18, 98, 0, 0, 0, 0, 203, 138, 9, 0, 44, 1, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 97, 0, 0, 8, 0, 0, 0, 6, 112, 124, 198, 169, 153, 1, 0, 1, 97,
            0, 0, 56, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0, 50, 49, 65, 53, 53, 57, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 77, 97, 99, 66, 111, 111, 107, 80, 114, 111, 49, 54, 44, 49, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 97, 0, 0, 24, 0, 0, 0, 195, 32, 184, 206, 151,
            250, 77, 165, 159, 49, 125, 57, 46, 56, 156, 234, 85, 0, 0, 0, 0, 0, 0, 0, 3, 97, 0, 0,
            48, 0, 0, 0, 47, 118, 97, 114, 47, 100, 98, 47, 116, 105, 109, 101, 122, 111, 110, 101,
            47, 122, 111, 110, 101, 105, 110, 102, 111, 47, 65, 109, 101, 114, 105, 99, 97, 47, 78,
            101, 119, 95, 89, 111, 114, 107, 0, 0, 0, 0, 0, 0,
        ];
        let mut data = UnifiedLogData {
            header: Vec::new(),
            catalog_data: Vec::new(),
            oversize: Vec::new(),
        };

        InternalLogData::get_header_data(&test_chunk_header, &mut data);
        assert_eq!(data.header.len(), 1);
    }

    #[test]
    fn test_get_catalog_data() {
        let test_chunk_catalog = [
            11, 96, 0, 0, 17, 0, 0, 0, 208, 1, 0, 0, 0, 0, 0, 0, 32, 0, 96, 0, 1, 0, 160, 0, 7, 0,
            0, 0, 0, 0, 0, 0, 20, 165, 44, 35, 253, 233, 2, 0, 43, 239, 210, 12, 24, 236, 56, 56,
            129, 79, 43, 78, 90, 243, 188, 236, 61, 5, 132, 95, 63, 101, 53, 143, 158, 191, 34, 54,
            231, 114, 172, 1, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 83, 107, 121, 76, 105,
            103, 104, 116, 0, 112, 101, 114, 102, 111, 114, 109, 97, 110, 99, 101, 95, 105, 110,
            115, 116, 114, 117, 109, 101, 110, 116, 97, 116, 105, 111, 110, 0, 116, 114, 97, 99,
            105, 110, 103, 46, 115, 116, 97, 108, 108, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 158,
            0, 0, 0, 0, 0, 0, 0, 55, 1, 0, 0, 158, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 87, 0, 0, 0, 19, 0, 78, 0, 0, 0, 47, 0, 0, 0, 0, 0,
            246, 113, 118, 43, 250, 233, 2, 0, 62, 195, 90, 26, 9, 234, 2, 0, 120, 255, 0, 0, 0, 1,
            0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 48, 89, 60, 28, 9, 234, 2, 0,
            99, 50, 207, 40, 18, 234, 2, 0, 112, 240, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0,
            0, 0, 0, 19, 0, 47, 0, 153, 6, 208, 41, 18, 234, 2, 0, 0, 214, 108, 78, 32, 234, 2, 0,
            0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 128, 0, 87,
            79, 32, 234, 2, 0, 137, 5, 2, 205, 41, 234, 2, 0, 88, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 185, 11, 2, 205, 41, 234, 2, 0, 172, 57, 107,
            20, 56, 234, 2, 0, 152, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19,
            0, 47, 0, 53, 172, 105, 21, 56, 234, 2, 0, 170, 167, 194, 43, 68, 234, 2, 0, 144, 255,
            0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 220, 202, 171, 57,
            68, 234, 2, 0, 119, 171, 170, 119, 76, 234, 2, 0, 240, 254, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
        ];
        let mut data = UnifiedLogCatalogData {
            catalog: CatalogChunk {
                chunk_tag: 0,
                chunk_sub_tag: 0,
                chunk_data_size: 0,
                catalog_subsystem_strings_offset: 0,
                catalog_process_info_entries_offset: 0,
                number_process_information_entries: 0,
                catalog_offset_sub_chunks: 0,
                number_sub_chunks: 0,
                unknown: Vec::new(),
                earliest_firehose_timestamp: 0,
                catalog_uuids: Vec::new(),
                catalog_subsystem_strings: Vec::new(),
                catalog_process_info_entries: Vec::new(),
                catalog_subchunks: Vec::new(),
            },
            firehose: Vec::new(),
            simpledump: Vec::new(),
            statedump: Vec::new(),
            oversize: Vec::new(),
        };

        InternalLogData::get_catalog_data(&test_chunk_catalog, &mut data);
        assert_eq!(data.catalog.chunk_tag, 0x600b);
        assert_eq!(data.catalog.chunk_sub_tag, 17);
        assert_eq!(data.catalog.chunk_data_size, 464);
        assert_eq!(data.catalog.catalog_subsystem_strings_offset, 32);
        assert_eq!(data.catalog.catalog_process_info_entries_offset, 96);
        assert_eq!(data.catalog.number_process_information_entries, 1);
        assert_eq!(data.catalog.catalog_offset_sub_chunks, 160);
        assert_eq!(data.catalog.number_sub_chunks, 7);
        assert_eq!(data.catalog.unknown, [0, 0, 0, 0, 0, 0]);
        assert_eq!(data.catalog.earliest_firehose_timestamp, 820223379547412);
        assert_eq!(
            data.catalog.catalog_uuids,
            [
                "2BEFD20C18EC3838814F2B4E5AF3BCEC",
                "3D05845F3F65358F9EBF2236E772AC01"
            ]
        );
        assert_eq!(
            data.catalog.catalog_subsystem_strings,
            [
                99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 83, 107, 121, 76, 105, 103, 104, 116,
                0, 112, 101, 114, 102, 111, 114, 109, 97, 110, 99, 101, 95, 105, 110, 115, 116,
                114, 117, 109, 101, 110, 116, 97, 116, 105, 111, 110, 0, 116, 114, 97, 99, 105,
                110, 103, 46, 115, 116, 97, 108, 108, 115, 0, 0, 0
            ]
        );
        assert_eq!(data.catalog.catalog_process_info_entries.len(), 1);
        assert_eq!(
            data.catalog.catalog_process_info_entries[0].main_uuid,
            "2BEFD20C18EC3838814F2B4E5AF3BCEC"
        );
        assert_eq!(
            data.catalog.catalog_process_info_entries[0].dsc_uuid,
            "3D05845F3F65358F9EBF2236E772AC01"
        );

        assert_eq!(data.catalog.catalog_subchunks.len(), 7)
    }

    #[test]
    fn test_get_chunkset_data() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Chunkset Tests/high_sierra_compressed_chunkset.raw");

        let buffer = fs::read(test_path).unwrap();

        let mut unified_log = UnifiedLogCatalogData {
            catalog: CatalogChunk {
                chunk_tag: 0,
                chunk_sub_tag: 0,
                chunk_data_size: 0,
                catalog_subsystem_strings_offset: 0,
                catalog_process_info_entries_offset: 0,
                number_process_information_entries: 0,
                catalog_offset_sub_chunks: 0,
                number_sub_chunks: 0,
                unknown: Vec::new(),
                earliest_firehose_timestamp: 0,
                catalog_uuids: Vec::new(),
                catalog_subsystem_strings: Vec::new(),
                catalog_process_info_entries: Vec::new(),
                catalog_subchunks: Vec::new(),
            },
            firehose: Vec::new(),
            simpledump: Vec::new(),
            statedump: Vec::new(),
            oversize: Vec::new(),
        };

        let mut log_data = UnifiedLogData {
            header: Vec::new(),
            catalog_data: Vec::new(),
            oversize: Vec::new(),
        };

        InternalLogData::get_chunkset_data(&buffer, &mut unified_log, &mut log_data);
        assert_eq!(unified_log.catalog.chunk_tag, 0);
        assert_eq!(unified_log.firehose.len(), 21);
        assert_eq!(unified_log.statedump.len(), 0);
        assert_eq!(unified_log.simpledump.len(), 0);
        assert_eq!(unified_log.oversize.len(), 0);

        assert_eq!(
            unified_log.firehose[0].public_data[0].message.item_info[0].message_strings,
            "483.700"
        );
        assert_eq!(unified_log.firehose[0].base_continous_time, 0);
        assert_eq!(unified_log.firehose[0].first_number_proc_id, 70);
        assert_eq!(unified_log.firehose[0].second_number_proc_id, 71);
        assert_eq!(unified_log.firehose[0].public_data_size, 4040);
        assert_eq!(unified_log.firehose[0].private_data_virtual_offset, 4096);
    }
}
