// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Registry credentials: Basic auth, the docker auth file, Bearer
//! challenges and the token a token server answers with.

use core::ffi::{CStr, c_int};

use super::{
    BASIC_RAW_SIZE, MAX_ENDPOINT, OciClient, PATH_MAX, at, cstr, find, is_space, strscpy,
    strsprintf,
};
use crate::errno::{E2BIG, EINVAL, ENAMETOOLONG, ENOENT, ENOMEM, ENOSPC};
use crate::sys::libc;
use crate::util::io;
use crate::util::json::{JsonField, parse_schema};

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The `user:password` that the base64 at the start of `s` encodes, up
/// to a NUL or a quote, blanks and padding skipped, into `user` and
/// `pass`.
pub(super) fn decode_basic(s: &[u8], user: &mut [u8], pass: &mut [u8]) -> c_int {
    let mut out = [0u8; BASIC_RAW_SIZE];
    let ret = decode_basic_into(s, &mut out, user, pass);

    libc::scrub(&mut out);
    ret
}

fn decode_basic_into(
    s: &[u8],
    out: &mut [u8; BASIC_RAW_SIZE],
    user: &mut [u8],
    pass: &mut [u8],
) -> c_int {
    let mut bits = -8;
    let mut n = 0;
    let mut val = 0u32;

    for &c in s {
        if c == 0 || c == b'"' || n >= out.len() {
            break;
        }
        if is_space(c) || c == b'=' {
            continue;
        }
        let Some(x) = base64_value(c) else {
            return -EINVAL;
        };
        // No more than 12 bits are ever pending.
        val = ((val << 6) | x) & 0xfff;
        bits += 6;
        if bits >= 0 {
            out[n] = (val >> bits) as u8;
            n += 1;
            bits -= 8;
        }
    }
    if n >= out.len() {
        return -E2BIG;
    }
    let decoded = &out[..n];
    if decoded.contains(&0) {
        return -EINVAL;
    }
    let Some(colon) = decoded.iter().position(|&c| c == b':') else {
        return -EINVAL;
    };
    if colon >= user.len() || n - colon > pass.len() {
        return -EINVAL;
    }
    user[..colon].copy_from_slice(&decoded[..colon]);
    user[colon] = 0;
    pass[..n - colon - 1].copy_from_slice(&decoded[colon + 1..]);
    pass[n - colon - 1] = 0;
    0
}

/// `user:pass` in base64 into `out`, terminated.
pub(super) fn encode_basic(user: &[u8], pass: &[u8], out: &mut [u8]) -> c_int {
    let mut raw = [0u8; BASIC_RAW_SIZE];
    let ret = encode_basic_from(user, pass, &mut raw, out);

    libc::scrub(&mut raw);
    ret
}

fn encode_basic_from(
    user: &[u8],
    pass: &[u8],
    raw: &mut [u8; BASIC_RAW_SIZE],
    out: &mut [u8],
) -> c_int {
    let Ok(len) = strsprintf(raw, &[user, b":", pass]) else {
        return -E2BIG;
    };
    let raw = &raw[..len];
    let mut o = 0;

    if 4 * len.div_ceil(3) + 1 > out.len() {
        return -ENOSPC;
    }
    for chunk in raw.chunks(3) {
        let v =
            (u32::from(chunk[0]) << 16) | (u32::from(at(chunk, 1)) << 8) | u32::from(at(chunk, 2));

        out[o] = BASE64[(v >> 18) as usize & 63];
        out[o + 1] = BASE64[(v >> 12) as usize & 63];
        out[o + 2] = if chunk.len() > 1 {
            BASE64[(v >> 6) as usize & 63]
        } else {
            b'='
        };
        out[o + 3] = if chunk.len() > 2 {
            BASE64[v as usize & 63]
        } else {
            b'='
        };
        o += 4;
    }
    out[o] = 0;
    0
}

/// The credentials for `registry`: BPM_OCI_USERNAME and BPM_OCI_PASSWORD,
/// or the `auth` of its entry in REGISTRY_AUTH_FILE or the docker
/// config, none when there is no file or no entry.
pub(super) fn load_registry_auth(registry: &[u8], c: &mut OciClient) -> c_int {
    let authfile = libc::env(c"REGISTRY_AUTH_FILE");
    let username = libc::env(c"BPM_OCI_USERNAME");
    let password = libc::env(c"BPM_OCI_PASSWORD");
    let docker = libc::env(c"DOCKER_CONFIG");
    let mut needle = [0u8; MAX_ENDPOINT + 8];
    let mut path = [0u8; PATH_MAX];

    if let (Some(username), Some(password)) = (username, password) {
        if strscpy(&mut c.username, username.to_bytes()).is_err()
            || strscpy(&mut c.password, password.to_bytes()).is_err()
        {
            return -E2BIG;
        }
        return 0;
    }
    let authfile = match (authfile, docker) {
        (Some(file), _) => file.to_bytes_with_nul(),
        (None, Some(docker)) => {
            if strsprintf(&mut path, &[docker.to_bytes(), b"/config.json"]).is_err() {
                return -ENAMETOOLONG;
            }
            &path[..]
        }
        (None, None) => {
            let home = libc::env(c"HOME").map_or(&b"/root"[..], CStr::to_bytes);

            if strsprintf(&mut path, &[home, b"/.docker/config.json"]).is_err() {
                return -ENAMETOOLONG;
            }
            &path[..]
        }
    };
    if strsprintf(&mut needle, &[b"\"", registry, b"\""]).is_err() {
        return -ENAMETOOLONG;
    }
    let Ok(authfile) = CStr::from_bytes_until_nul(authfile) else {
        return -EINVAL;
    };
    let body = match io::read(authfile, 4 * 1024 * 1024) {
        Ok(body) => body,
        Err(err) => return if err == -ENOENT { 0 } else { err },
    };
    auth_entry(&body, cstr(&needle), c)
}

/// The auth file is local input; the registry key and its auth member
/// must sit in one JSON object before the credentials count.
pub(super) fn auth_entry(text: &[u8], needle: &[u8], c: &mut OciClient) -> c_int {
    if text.contains(&0) {
        return -EINVAL;
    }
    let Some(p) = find(text, needle) else {
        return 0;
    };
    let rest = &text[p..];
    let Some(end) = rest.iter().position(|&c| c == b'}') else {
        return -EINVAL;
    };
    let auth = match find(rest, b"\"auth\"") {
        Some(auth) if auth <= end => auth,
        _ => return 0,
    };
    let Some(colon) = rest[auth..].iter().position(|&c| c == b':') else {
        return -EINVAL;
    };
    let mut i = auth + colon + 1;
    while i < rest.len() && is_space(rest[i]) {
        i += 1;
    }
    if at(rest, i) != b'"' {
        return -EINVAL;
    }
    decode_basic(&rest[i + 1..], &mut c.username, &mut c.password)
}

/// The parameters of a challenge with the given, complete scheme.
pub(super) fn challenge_params<'a>(header: &'a [u8], scheme: &[u8]) -> Option<&'a [u8]> {
    let (head, rest) = header.split_at_checked(scheme.len())?;
    (head.eq_ignore_ascii_case(scheme) && (rest.is_empty() || rest.starts_with(b" ")))
        .then_some(rest)
}

#[derive(Default)]
pub(super) struct BearerChallenge<'a> {
    pub realm: &'a [u8],
    pub service: &'a [u8],
    pub scope: &'a [u8],
}

pub(super) fn parse_challenge(header: &[u8]) -> Result<BearerChallenge<'_>, c_int> {
    let mut fields = BearerChallenge::default();
    let mut params = challenge_params(header, b"Bearer").ok_or(-EINVAL)?;

    while !params.is_empty() {
        let start = params
            .iter()
            .take_while(|&&c| matches!(c, b' ' | b','))
            .count();
        params = &params[start..];
        let (value, field, cap) = if let Some(value) = params.strip_prefix(b"realm=\"") {
            (value, &mut fields.realm, PATH_MAX)
        } else if let Some(value) = params.strip_prefix(b"service=\"") {
            (value, &mut fields.service, 256)
        } else if let Some(value) = params.strip_prefix(b"scope=\"") {
            (value, &mut fields.scope, 512)
        } else {
            let Some(comma) = params.iter().position(|&c| c == b',') else {
                break;
            };
            params = &params[comma + 1..];
            continue;
        };
        let end = value.iter().position(|&c| c == b'"').ok_or(-EINVAL)?;
        if end >= cap {
            return Err(-ENAMETOOLONG);
        }
        *field = &value[..end];
        params = &value[end + 1..];
    }

    if fields.realm.is_empty() {
        return Err(-EINVAL);
    }
    Ok(fields)
}

/// The token server's own token member, falling back to access_token.
pub(super) fn token_from_body(body: &[u8], out: &mut [u8]) -> Result<(), c_int> {
    if body.contains(&0) || out.is_empty() {
        return Err(-EINVAL);
    }
    let room = out.len().checked_mul(2).ok_or(-ENOMEM)?;
    let mut storage = Vec::new();
    storage.try_reserve_exact(room).map_err(|_| -ENOMEM)?;
    storage.resize(room, 0);
    let mut tokens = storage.split_at_mut(out.len());
    let fields = [
        JsonField::string(c"token", |tokens: &mut (&mut [u8], &mut [u8])| tokens.0),
        JsonField::string(c"access_token", |tokens| tokens.1),
    ];

    parse_schema(body, &fields, &mut tokens).map_err(|_| -EINVAL)?;
    let token = if fields[0].seen() {
        cstr(tokens.0)
    } else if fields[1].seen() {
        cstr(tokens.1)
    } else {
        return Err(-EINVAL);
    };
    // The decoded token goes straight into the Authorization header.
    if token
        .iter()
        .any(|&c| c < 0x21 || matches!(c, b'"' | b'\\' | 0x7f))
    {
        return Err(-EINVAL);
    }
    strscpy(out, token).map(|_| ())
}
