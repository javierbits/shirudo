// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The temporary copy of an OCI package pinned by its manifest digest.

use core::ffi::{CStr, c_int};
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

use super::{archive, build::cstring, error, last_err, path};
use crate::errno::{EINVAL, EKEYREJECTED, ENOENT};
use crate::text::cstr;
use crate::util::bpm_oci::{Client, MANIFEST_MEDIA, digest_matches, manifest_layers, sha256_hex};

const PACKAGE_MEDIA: &CStr = c"application/vnd.shirudo.bpm.package.v1+gzip";

pub(super) fn digest_ok(digest: &[u8]) -> bool {
    digest.strip_prefix(b"sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// A private temporary file removed when the command is done with it.
pub(super) struct Download(CString);

impl Download {
    pub(super) fn path(&self) -> &CStr {
        &self.0
    }

    fn create(template: &CStr) -> Result<(Self, OwnedFd), c_int> {
        let mut template = template.to_bytes_with_nul().to_vec();
        // SAFETY: the writable, NUL-terminated mkstemp template.
        let fd = unsafe { crate::sys::libc::mkstemp(template.as_mut_ptr().cast()) };
        if fd < 0 {
            return Err(last_err());
        }
        // SAFETY: mkstemp returned this new descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok((Self(cstring(cstr(&template))), fd))
    }

    /// The package of the manifest the operator pinned.
    pub(super) fn fetch(
        command: &[u8],
        reference: &[u8],
        want: &[u8],
        template: &CStr,
    ) -> Result<Self, c_int> {
        let mut client = Client::new();
        let (repo, tag) = client.parse_pull_ref(reference)?;
        let url = client.url(&repo, b"manifests", &tag)?;
        let manifest = client.get(&url, MANIFEST_MEDIA, false)?;
        let mut hex = [0; 65];
        if sha256_hex(manifest.bytes(), &mut hex) != 0 {
            return Err(-EINVAL);
        }
        let served = cstr(&hex);
        if !digest_matches(want, served) {
            error(
                &[
                    command,
                    b": ",
                    reference,
                    b" serves manifest sha256:",
                    served,
                    b", not ",
                    want,
                ]
                .concat(),
            );
            return Err(-EKEYREJECTED);
        }
        let (layers, _) = manifest_layers(manifest.bytes(), 8, false)?;
        let layer = layers
            .iter()
            .find(|layer| layer.media() == PACKAGE_MEDIA.to_bytes())
            .ok_or(-ENOENT)?;
        let url = client.url(&repo, b"blobs", layer.digest())?;
        let (file, fd) = Self::create(template)?;
        let transfer = client.get_file(&url, PACKAGE_MEDIA, fd.as_raw_fd(), layer.size());
        // SAFETY: ownership of the descriptor passes from OwnedFd to close.
        let closed = unsafe { crate::sys::libc::close(fd.into_raw_fd()) };
        let closed = if closed == 0 { Ok(()) } else { Err(last_err()) };
        transfer.and(closed)?;

        let body = archive::read_file(file.path().to_bytes(), archive::MAX_FILE)?;
        if sha256_hex(&body, &mut hex) != 0 || !digest_matches(layer.digest(), cstr(&hex)) {
            return Err(-EKEYREJECTED);
        }
        Ok(file)
    }
}

impl Drop for Download {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(path(self.path().to_bytes()));
    }
}
