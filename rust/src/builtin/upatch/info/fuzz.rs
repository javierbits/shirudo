// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-upatch-info: unverified upatch metadata printed as text and JSON.

use std::sync::OnceLock;

use crate::fuzzing::{StdoutCapture, fuzz_target, input_file};

static OUTPUT: OnceLock<StdoutCapture> = OnceLock::new();

fuzz_target!(
    shirudo_fuzz_upatch_info,
    shirudo_fuzz_upatch_info_init,
    |bytes| {
        let Some(input) = input_file(bytes) else {
            return;
        };
        let output = OUTPUT.get_or_init(StdoutCapture::new);

        let _ = super::run(&[c"info", input.path.as_c_str()]);
        output.check(false);
        let _ = super::run(&[c"info", input.path.as_c_str(), c"--json"]);
        output.check(true);
    }
);
