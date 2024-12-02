// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::path::{Path, PathBuf};

use criterion::{criterion_group, criterion_main, Criterion};
use macos_unifiedlogs::{
    dsc::SharedCacheStrings,
    parser::{
        buffer_from_path, build_log, collect_shared_strings, collect_strings, collect_timesync,
        parse_log,
    },
    timesync::TimesyncBoot,
    unified_log::UnifiedLogData,
    uuidtext::UUIDText,
};

fn big_sur_parse_log(path: &Path) {
    let buffer = buffer_from_path(path).unwrap();
    let _ = parse_log(&buffer).unwrap();
}

fn bench_build_log(
    log_data: &UnifiedLogData,
    string_results: &Vec<UUIDText>,
    shared_strings_results: &Vec<SharedCacheStrings>,
    timesync_data: &Vec<TimesyncBoot>,
) {
    let _ = build_log(
        &log_data,
        &string_results,
        &shared_strings_results,
        &timesync_data,
    );
}

fn big_sur_single_log_benchpress(c: &mut Criterion) {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path
        .push("tests/test_data/system_logs_big_sur.logarchive/Persist/0000000000000004.tracev3");

    c.bench_function("Benching Parsing One Big Sur Log", |b| {
        b.iter(|| big_sur_parse_log(&test_path))
    });
}

fn big_sur_build_log_benchbress(c: &mut Criterion) {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");
    let string_results = collect_strings(&test_path).unwrap();

    test_path.push("dsc");
    let shared_strings_results = collect_shared_strings(&test_path).unwrap();
    test_path.pop();

    test_path.push("timesync");
    let timesync_data = collect_timesync(&test_path).unwrap();
    test_path.pop();

    test_path.push("Persist/0000000000000004.tracev3");

    let buffer = buffer_from_path(&test_path).unwrap();
    let log_data = parse_log(&buffer).unwrap();

    c.bench_function("Benching Building One Big Sur Log", |b| {
        b.iter(|| {
            bench_build_log(
                &log_data,
                &string_results,
                &shared_strings_results,
                &timesync_data,
            )
        })
    });
}

criterion_group!(
    benches,
    big_sur_single_log_benchpress,
    big_sur_build_log_benchbress
);
criterion_main!(benches);
