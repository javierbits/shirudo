// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::sys::libc::PATH_MAX;

#[test]
fn old_unload_path_error_stops_the_scan() {
    let mut dir = vec![b'a'; PATH_MAX - b"/last.unload.upatch".len()];
    dir[0] = b'/';
    let dir = CString::new(dir).unwrap();
    let first = OsString::from("one.unload.upatch");
    let last = OsString::from("last.unload.upatch");

    let pairs = collect_old_pairs(&dir, [first.clone()].into_iter()).unwrap();
    assert_eq!(pairs.len(), 1);
    assert_eq!(
        collect_old_pairs(&dir, [first, last].into_iter()),
        Err(-ENAMETOOLONG),
    );
}
