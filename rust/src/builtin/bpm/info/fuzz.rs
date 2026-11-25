// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-bpm-info: README, member listing and .rodata output of a package.

use std::os::fd::AsFd;
use std::sync::OnceLock;

use super::{Archive, cstr, data, readme, upatches, visit_members_fd};
use crate::fuzzing::{StdoutCapture, fuzz_target, input_gzip_file};

const MAX_MEMBERS: usize = 4;
static OUTPUT: OnceLock<StdoutCapture> = OnceLock::new();

fn data_members(source: &[u8]) -> Vec<Vec<u8>> {
    let mut members = Vec::new();
    let Ok(archive) = Archive::open(source) else {
        return members;
    };
    let mut dir = [0; 101];
    if archive.beefile(&mut dir).is_ok() {
        visit_members_fd(archive.0.as_fd(), Some(cstr(&dir)), &mut |name, kind| {
            let name = name.to_bytes();
            if members.len() < MAX_MEMBERS && kind == b'0' as _ && name.starts_with(b"upatches/") {
                members.push(name.to_vec());
            }
            0
        });
    }
    members
}

fuzz_target!(shirudo_fuzz_bpm_info, shirudo_fuzz_bpm_info_init, |bytes| {
    let Some(input) = input_gzip_file(bytes) else {
        return;
    };
    let source = input.path.to_bytes();
    let output = OUTPUT.get_or_init(StdoutCapture::new);

    let _ = readme(source);
    output.check(false);
    let _ = upatches(source, true);
    output.check(false);
    for member in data_members(source) {
        for json in [false, true] {
            let _ = data(source, &member, json);
            output.check(json);
        }
    }
});
