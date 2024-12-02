// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

/// Return BOOL value to string
pub fn uppercase_bool(bool_data: &str) -> &'static str {
    if bool_data == "0" {
        return "NO";
    }
    "YES"
}

/// Return bool value to string
pub fn lowercase_bool(bool_data: &str) -> &'static str {
    if bool_data == "0" {
        return "false";
    }
    "true"
}

/// Return int value to bool
pub fn lowercase_int_bool(bool_data: &u8) -> &'static str {
    let false_bool = 0;
    if bool_data == &false_bool {
        return "false";
    }
    "true"
}

#[cfg(test)]
mod tests {
    use crate::decoders::bool::{lowercase_bool, lowercase_int_bool, uppercase_bool};

    #[test]
    fn test_uppercase_bool() {
        let mut test_data = "0";
        let mut results = uppercase_bool(test_data);
        assert_eq!(results, "NO");

        test_data = "1";
        results = uppercase_bool(test_data);
        assert_eq!(results, "YES");
    }

    #[test]
    fn test_lowercase_bool() {
        let mut test_data = "0";
        let mut results = lowercase_bool(test_data);
        assert_eq!(results, "false");

        test_data = "1";
        results = lowercase_bool(test_data);
        assert_eq!(results, "true");
    }

    #[test]
    fn test_lowercase_int_bool() {
        let test_data = 0;
        let results = lowercase_int_bool(&test_data);
        assert_eq!(results, "false");
    }
}
