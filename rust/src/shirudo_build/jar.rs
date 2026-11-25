// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The manifest of a jar, read from its ZIP central directory, and the
//! `Premain-Class` attribute a Java agent needs in it.

use core::ffi::c_int;

use miniz_oxide::inflate::decompress_slice_iter_to_slice;

use crate::errno::{EFBIG, EINVAL, ENOENT, ENOMEM, EOPNOTSUPP};

const ZIP_END_SIG: u32 = 0x0605_4b50;
const ZIP_END_LEN: usize = 22;
const ZIP_COMMENT_MAX: usize = 65_535;
const ZIP_ENTRY_SIG: u32 = 0x0201_4b50;
const ZIP_ENTRY_LEN: usize = 46;
const ZIP_LOCAL_SIG: u32 = 0x0403_4b50;
const ZIP_LOCAL_LEN: usize = 30;
const ZIP_STORED: u16 = 0;
const ZIP_DEFLATED: u16 = 8;
const JAR_MANIFEST_MAX: usize = 1 << 20;
const MANIFEST_NAME: &[u8] = b"META-INF/MANIFEST.MF";
const PREMAIN_ATTR: &[u8] = b"Premain-Class:";

struct Entry {
    method: u16,
    packed_len: usize,
    len: usize,
    local_off: usize,
}

fn in_bounds(off: usize, need: usize, len: usize) -> bool {
    off <= len && need <= len - off
}

fn le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// The central directory offset and number of entries. The end record is
/// last but for a comment, so the search runs backward.
fn directory(zip: &[u8]) -> Result<(usize, usize), c_int> {
    if zip.len() < ZIP_END_LEN {
        return Err(-EINVAL);
    }
    let high = zip.len() - ZIP_END_LEN;
    let low = high.saturating_sub(ZIP_COMMENT_MAX);
    let at = (low..=high)
        .rev()
        .find(|&at| le32(zip, at) == ZIP_END_SIG)
        .ok_or(-EINVAL)?;
    let entries = usize::from(le16(zip, at + 10));
    let dir = le32(zip, at + 16);

    if entries == usize::from(u16::MAX) || dir == u32::MAX {
        return Err(-EOPNOTSUPP);
    }
    let dir = usize::try_from(dir).map_err(|_| -EINVAL)?;
    if dir > at {
        return Err(-EINVAL);
    }
    Ok((dir, entries))
}

/// The central-directory entry named `name`, compared as the JVM compares
/// the manifest name.
fn find(zip: &[u8], name: &[u8]) -> Result<Entry, c_int> {
    let (mut off, entries) = directory(zip)?;

    for _ in 0..entries {
        if !in_bounds(off, ZIP_ENTRY_LEN, zip.len()) || le32(zip, off) != ZIP_ENTRY_SIG {
            return Err(-EINVAL);
        }
        let name_len = usize::from(le16(zip, off + 28));
        let skip = usize::from(le16(zip, off + 30)) + usize::from(le16(zip, off + 32));
        let names = off + ZIP_ENTRY_LEN;
        let tail = name_len.checked_add(skip).ok_or(-EINVAL)?;
        if !in_bounds(names, tail, zip.len()) {
            return Err(-EINVAL);
        }
        if name_len == name.len() && zip[names..names + name_len].eq_ignore_ascii_case(name) {
            return Ok(Entry {
                method: le16(zip, off + 10),
                packed_len: usize::try_from(le32(zip, off + 20)).map_err(|_| -EINVAL)?,
                len: usize::try_from(le32(zip, off + 24)).map_err(|_| -EINVAL)?,
                local_off: usize::try_from(le32(zip, off + 42)).map_err(|_| -EINVAL)?,
            });
        }
        off = names + tail;
    }
    Err(-ENOENT)
}

/// The entry's packed bytes, past its local header.
fn entry_data<'a>(zip: &'a [u8], entry: &Entry) -> Result<&'a [u8], c_int> {
    let off = entry.local_off;
    if !in_bounds(off, ZIP_LOCAL_LEN, zip.len()) || le32(zip, off) != ZIP_LOCAL_SIG {
        return Err(-EINVAL);
    }
    let skip = usize::from(le16(zip, off + 26)) + usize::from(le16(zip, off + 28));
    let data = off + ZIP_LOCAL_LEN;
    if !in_bounds(data, skip, zip.len()) || !in_bounds(data + skip, entry.packed_len, zip.len()) {
        return Err(-EINVAL);
    }
    Ok(&zip[data + skip..data + skip + entry.packed_len])
}

/// The uncompressed bytes of one entry, bounded to the manifest limit.
fn read_entry(zip: &[u8], entry: &Entry) -> Result<Vec<u8>, c_int> {
    if entry.len > JAR_MANIFEST_MAX {
        return Err(-EFBIG);
    }
    if entry.method != ZIP_STORED && entry.method != ZIP_DEFLATED {
        return Err(-EOPNOTSUPP);
    }
    if entry.method == ZIP_STORED && entry.packed_len != entry.len {
        return Err(-EINVAL);
    }
    let packed = entry_data(zip, entry)?;
    let mut body = Vec::new();
    body.try_reserve_exact(entry.len).map_err(|_| -ENOMEM)?;
    body.resize(entry.len, 0);
    if entry.method == ZIP_STORED {
        body.copy_from_slice(packed);
    } else {
        let n = decompress_slice_iter_to_slice(&mut body, core::iter::once(packed), false, false)
            .map_err(|_| -EINVAL)?;
        if n != entry.len {
            return Err(-EINVAL);
        }
    }
    Ok(body)
}

fn line_end(c: u8) -> bool {
    c == b'\n' || c == b'\r'
}

/// Whether the main section, which the first empty line ends, has a
/// `Premain-Class` with a value.
fn manifest_has_premain(manifest: &[u8]) -> bool {
    let mut at = 0;

    while at < manifest.len() && !line_end(manifest[at]) {
        let mut end = at;
        while end < manifest.len() && !line_end(manifest[end]) {
            end += 1;
        }
        if end - at > PREMAIN_ATTR.len()
            && manifest[at..at + PREMAIN_ATTR.len()].eq_ignore_ascii_case(PREMAIN_ATTR)
        {
            return manifest[at + PREMAIN_ATTR.len()..end]
                .iter()
                .any(|&c| c != b' ');
        }
        at = end;
        if at < manifest.len() && manifest[at] == b'\r' {
            at += 1;
        }
        if at < manifest.len() && manifest[at] == b'\n' {
            at += 1;
        }
    }
    false
}

/// Checks that `jar` has a readable manifest whose main section gives a
/// non-empty `Premain-Class` attribute.
pub(super) fn premain_class(jar: &[u8]) -> Result<(), c_int> {
    let entry = find(jar, MANIFEST_NAME)?;
    let manifest = read_entry(jar, &entry)?;

    if manifest_has_premain(&manifest) {
        Ok(())
    } else {
        Err(-ENOENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniz_oxide::deflate::compress_to_vec;

    fn set16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn set32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn zip(name: &[u8], body: &[u8], method: u16) -> Vec<u8> {
        let packed = if method == ZIP_DEFLATED {
            compress_to_vec(body, 6)
        } else {
            body.to_vec()
        };
        let mut out = vec![0u8; ZIP_LOCAL_LEN];
        set32(&mut out, 0, ZIP_LOCAL_SIG);
        set16(&mut out, 8, method);
        set32(&mut out, 18, packed.len() as u32);
        set32(&mut out, 22, body.len() as u32);
        set16(&mut out, 26, name.len() as u16);
        out.extend_from_slice(name);
        out.extend_from_slice(&packed);

        let dir = out.len();
        out.resize(dir + ZIP_ENTRY_LEN, 0);
        set32(&mut out, dir, ZIP_ENTRY_SIG);
        set16(&mut out, dir + 10, method);
        set32(&mut out, dir + 20, packed.len() as u32);
        set32(&mut out, dir + 24, body.len() as u32);
        set16(&mut out, dir + 28, name.len() as u16);
        set32(&mut out, dir + 42, 0);
        out.extend_from_slice(name);

        let end = out.len();
        out.resize(end + ZIP_END_LEN, 0);
        set32(&mut out, end, ZIP_END_SIG);
        set16(&mut out, end + 8, 1);
        set16(&mut out, end + 10, 1);
        set32(&mut out, end + 12, (ZIP_ENTRY_LEN + name.len()) as u32);
        set32(&mut out, end + 16, dir as u32);
        out
    }

    #[test]
    fn stored_and_deflated_agent_manifests() {
        let body = b"Manifest-Version: 1.0\r\nPremain-Class: example.Agent\r\n\r\n";

        assert_eq!(premain_class(&zip(MANIFEST_NAME, body, ZIP_STORED)), Ok(()));
        assert_eq!(
            premain_class(&zip(MANIFEST_NAME, body, ZIP_DEFLATED)),
            Ok(())
        );
    }

    #[test]
    fn names_and_attribute_are_ascii_case_insensitive() {
        let body = b"manifest-version: 1.0\nPrEmAiN-cLaSs:\texample.Agent\n\n";

        assert_eq!(
            premain_class(&zip(b"meta-inf/manifest.mf", body, ZIP_STORED)),
            Ok(())
        );
    }

    #[test]
    fn missing_or_non_main_premain_is_not_an_agent() {
        let missing = zip(b"ordinary", b"Premain-Class: Agent\n", ZIP_STORED);
        let empty = zip(MANIFEST_NAME, b"Premain-Class:   \n", ZIP_STORED);
        let entry = zip(
            MANIFEST_NAME,
            b"Manifest-Version: 1.0\n\nName: x\nPremain-Class: Agent\n",
            ZIP_STORED,
        );

        assert_eq!(premain_class(&missing), Err(-ENOENT));
        assert_eq!(premain_class(&empty), Err(-ENOENT));
        assert_eq!(premain_class(&entry), Err(-ENOENT));
    }

    #[test]
    fn malformed_and_truncated_zips_are_rejected() {
        assert_eq!(premain_class(b"not a zip"), Err(-EINVAL));
        let jar = zip(MANIFEST_NAME, b"Premain-Class: Agent\n", ZIP_STORED);

        for n in 0..jar.len() {
            assert!(premain_class(&jar[..n]).is_err(), "accepted {n} bytes");
        }
    }

    #[test]
    fn unsupported_and_oversized_entries_are_rejected() {
        let unsupported = zip(MANIFEST_NAME, b"Premain-Class: Agent\n", 99);
        assert_eq!(premain_class(&unsupported), Err(-EOPNOTSUPP));

        let mut zip64 = zip(MANIFEST_NAME, b"Premain-Class: Agent\n", ZIP_STORED);
        let end = zip64.len() - ZIP_END_LEN;
        set16(&mut zip64, end + 10, u16::MAX);
        assert_eq!(premain_class(&zip64), Err(-EOPNOTSUPP));

        let mut huge = zip(MANIFEST_NAME, b"Premain-Class: Agent\n", ZIP_STORED);
        let dir = le32(&huge, huge.len() - ZIP_END_LEN + 16) as usize;
        set32(&mut huge, dir + 24, (JAR_MANIFEST_MAX + 1) as u32);
        assert_eq!(premain_class(&huge), Err(-EFBIG));
    }

    #[test]
    fn stored_lengths_and_deflate_stream_are_checked() {
        let mut stored = zip(MANIFEST_NAME, b"Premain-Class: Agent\n", ZIP_STORED);
        let dir = le32(&stored, stored.len() - ZIP_END_LEN + 16) as usize;
        set32(&mut stored, dir + 20, 1);
        assert_eq!(premain_class(&stored), Err(-EINVAL));

        let mut deflated = zip(MANIFEST_NAME, b"Premain-Class: Agent\n", ZIP_DEFLATED);
        let dir = le32(&deflated, deflated.len() - ZIP_END_LEN + 16) as usize;
        let packed = le32(&deflated, dir + 20) as usize;
        let data = ZIP_LOCAL_LEN + MANIFEST_NAME.len();
        deflated[data + packed / 2] ^= 0xff;
        assert!(premain_class(&deflated).is_err());
    }
}
