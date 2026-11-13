// Phone → desktop transfer package: a stream of records split into parts.
//
// HEADER : version ‖ package_id (16) ‖ flags (bit 0: with history) ‖ part size
// PART   : part number u32 ‖ stream bytes (each part is a separate link AEAD blob,
//          AAD = domain ‖ link_id ‖ seq ‖ kind)
// END    : parts u32 ‖ records u64 ‖ stream bytes u64 ‖ SHA-256(domain ‖ package_id ‖ stream)
// ACK    : (desktop → phone) the same checksum: "received in full".
//
// Stream record: section u8 ‖ id (u16 length) ‖ body (u32 length). Sections and limits
// are strict on BOTH sides: the package does not carry video or large files.
//

use sha2::{Digest, Sha256};

use super::codec::{Rd, W};
use super::{ct_eq, LinkError, DOMAIN, LR};

const PKG_VERSION: u8 = 1;
const FLAG_HISTORY: u8 = 1;
/// Plaintext size of one part. With the part number and AEAD tag the blob stays below
/// the relay limit (1 MiB).
pub const PACKAGE_CHUNK: usize = 960 * 1024;
/// Package stream limit: the relay accepts at most 64 MiB phone→desktop per link, 1 MiB
/// is reserved for ACCEPT, the certificate, MLS requests and control blobs. Whatever does not fit: photos via
/// /api/blob (SECTION_PHOTO_BLOB_REF).
pub const PACKAGE_MAX_BYTES: u64 = 63 * 1024 * 1024;

pub const SECTION_PROFILE: u8 = 1;
pub const SECTION_CONTACT: u8 = 2;
pub const SECTION_CHAT: u8 = 3;
pub const SECTION_MESSAGE_TEXT: u8 = 4;
pub const SECTION_MESSAGE_PHOTO: u8 = 5;
pub const SECTION_MLS_WELCOME: u8 = 6;
pub const SECTION_COMM_VAULT: u8 = 7;
pub const SECTION_COMM_MEMBERSHIP: u8 = 8;
/// Shared key of the account's devices (account_sync_key, 32 B): device names etc.
pub const SECTION_ACCOUNT_SYNC: u8 = 9;
/// History photo uploaded to /api/blob (body is the file reference and key, ≤ 4 KiB): used when the package
/// does not fit the relay limit (64 MiB). The "is a still image" check happens
/// on the desktop after download and decryption (link_is_still_image).
pub const SECTION_PHOTO_BLOB_REF: u8 = 10;

const ID_MAX: usize = 256;
const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;
/// Photos larger than this are not transferred (treated as a large file).
pub const PHOTO_MAX: usize = 16 * MIB;

/// Package record.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct PackageRecord {
    pub section: u8,
    pub id: Vec<u8>,
    pub body: Vec<u8>,
}

/// What arrived with the latest package blob.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct PackageProgress {
    /// Records fully assembled by this blob (in stream order).
    pub records: Vec<PackageRecord>,
    /// END accepted and the checksum matched: records may be committed to the database.
    pub done: bool,
    pub include_history: bool,
    pub parts: u32,
    pub bytes: u64,
}

struct Limits {
    id_min: usize,
    body_max: usize,
    history: bool,
    once: bool,
}

fn limits(section: u8) -> LR<Limits> {
    let l = |id_min, body_max, history, once| Limits { id_min, body_max, history, once };
    Ok(match section {
        SECTION_PROFILE => l(0, MIB, false, true),
        SECTION_CONTACT => l(1, 256 * KIB, false, false),
        SECTION_CHAT => l(1, 256 * KIB, false, false),
        SECTION_MESSAGE_TEXT => l(1, 256 * KIB, true, false),
        SECTION_MESSAGE_PHOTO => l(1, PHOTO_MAX, true, false),
        SECTION_MLS_WELCOME => l(1, MIB, false, false),
        SECTION_COMM_VAULT => l(0, 64, false, true),
        SECTION_COMM_MEMBERSHIP => l(1, 256 * KIB, false, false),
        SECTION_ACCOUNT_SYNC => l(0, 32, false, true),
        SECTION_PHOTO_BLOB_REF => l(1, 4 * KIB, true, false),
        s => return Err(LinkError::Malformed(format!("unknown package section {s}"))),
    })
}

/// Still images only, by signature: JPEG, PNG, GIF, WebP, HEIC/HEIF, AVIF.
/// Video in an ISO BMFF container (mp4/mov/3gp/HEIF sequences) is rejected.
#[uniffi::export]
pub fn link_is_still_image(bytes: Vec<u8>) -> bool {
    is_still_image(&bytes)
}

pub(crate) fn is_still_image(b: &[u8]) -> bool {
    if b.len() < 12 {
        return false;
    }
    if b.starts_with(&[0xFF, 0xD8, 0xFF]) || b.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return true;
    }
    if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        return true;
    }
    if &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        return true;
    }
    if &b[4..8] == b"ftyp" {
        return matches!(&b[8..12], b"heic" | b"heix" | b"mif1" | b"avif");
    }
    false
}

fn check_record(section: u8, id: &[u8], body: &[u8], include_history: bool, seen: &mut [bool; 256]) -> LR<()> {
    let l = limits(section)?;
    if l.history && !include_history {
        return Err(LinkError::Malformed(format!("section {section} needs \"with history\"")));
    }
    if id.len() < l.id_min || id.len() > ID_MAX {
        return Err(LinkError::Malformed(format!("section {section}: id length {}", id.len())));
    }
    if body.len() > l.body_max {
        return Err(LinkError::Malformed(format!("section {section}: body {} > {}", body.len(), l.body_max)));
    }
    if section == SECTION_COMM_VAULT && body.len() != 64 {
        return Err(LinkError::Malformed("communities vault roots must be 64 bytes".into()));
    }
    if section == SECTION_ACCOUNT_SYNC && body.len() != 32 {
        return Err(LinkError::Malformed("account sync key must be 32 bytes".into()));
    }
    if section == SECTION_MESSAGE_PHOTO && !is_still_image(body) {
        return Err(LinkError::Malformed("only still images are transferred".into()));
    }
    if l.once {
        if seen[section as usize] {
            return Err(LinkError::Malformed(format!("section {section} may appear once")));
        }
        seen[section as usize] = true;
    }
    Ok(())
}

fn digest_init(package_id: &[u8; 16]) -> Sha256 {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(b"/package");
    h.update(package_id);
    h
}

pub(crate) struct PackageWriter {
    buf: Vec<u8>,
    hash: Option<Sha256>,
    include_history: bool,
    next_part: u32,
    records: u64,
    bytes: u64,
    seen: [bool; 256],
    digest: Option<[u8; 32]>,
}

impl PackageWriter {
    pub fn begin(package_id: [u8; 16], include_history: bool) -> (Self, Vec<u8>) {
        let mut w = W::new();
        w.u8(PKG_VERSION).raw(&package_id).u8(if include_history { FLAG_HISTORY } else { 0 }).u32(PACKAGE_CHUNK as u32);
        (
            PackageWriter {
                buf: Vec::new(),
                hash: Some(digest_init(&package_id)),
                include_history,
                next_part: 0,
                records: 0,
                bytes: 0,
                seen: [false; 256],
                digest: None,
            },
            w.done(),
        )
    }

    fn cut(&mut self, all: bool) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while self.buf.len() >= PACKAGE_CHUNK || (all && !self.buf.is_empty()) {
            let n = self.buf.len().min(PACKAGE_CHUNK);
            let mut w = W::new();
            w.u32(self.next_part).raw(&self.buf[..n]);
            self.buf.drain(..n);
            self.next_part += 1;
            out.push(w.done());
        }
        out
    }

    pub fn add(&mut self, section: u8, id: &[u8], body: &[u8]) -> LR<Vec<Vec<u8>>> {
        let h = self.hash.as_mut().ok_or_else(|| LinkError::State("package already finished".into()))?;
        check_record(section, id, body, self.include_history, &mut self.seen)?;
        let mut w = W::new();
        w.u8(section).b16(id).b32(body);
        let rec = w.done();
        if self.bytes + rec.len() as u64 > PACKAGE_MAX_BYTES {
            return Err(LinkError::Malformed("package budget exceeded: send the rest of the photos via /api/blob".into()));
        }
        h.update(&rec);
        self.bytes += rec.len() as u64;
        self.records += 1;
        self.buf.extend_from_slice(&rec);
        Ok(self.cut(false))
    }

    pub fn finish(&mut self) -> LR<(Vec<Vec<u8>>, Vec<u8>)> {
        let h = self.hash.take().ok_or_else(|| LinkError::State("package already finished".into()))?;
        let parts = self.cut(true);
        let digest: [u8; 32] = h.finalize().into();
        let mut w = W::new();
        w.u32(self.next_part).u64(self.records).u64(self.bytes).raw(&digest);
        self.digest = Some(digest);
        Ok((parts, w.done()))
    }

    pub fn digest(&self) -> Option<Vec<u8>> {
        self.digest.map(|d| d.to_vec())
    }
}

pub(crate) struct PackageReader {
    buf: Vec<u8>,
    hash: Option<Sha256>,
    include_history: bool,
    next_part: u32,
    records: u64,
    bytes: u64,
    seen: [bool; 256],
    digest: Option<[u8; 32]>,
}

impl PackageReader {
    pub fn begin(header: &[u8]) -> LR<(Self, PackageProgress)> {
        let mut r = Rd::new(header, "package header");
        let v = r.u8()?;
        if v != PKG_VERSION {
            return Err(LinkError::Malformed(format!("package version {v}")));
        }
        let package_id = r.arr::<16>()?;
        let flags = r.u8()?;
        if flags & !FLAG_HISTORY != 0 {
            return Err(LinkError::Malformed(format!("package flags {flags:#x}")));
        }
        let chunk = r.u32()?;
        if chunk as usize != PACKAGE_CHUNK {
            return Err(LinkError::Malformed(format!("package chunk size {chunk}")));
        }
        r.end()?;
        let rd = PackageReader {
            buf: Vec::new(),
            hash: Some(digest_init(&package_id)),
            include_history: flags & FLAG_HISTORY != 0,
            next_part: 0,
            records: 0,
            bytes: 0,
            seen: [false; 256],
            digest: None,
        };
        let p = rd.progress(Vec::new());
        Ok((rd, p))
    }

    fn progress(&self, records: Vec<PackageRecord>) -> PackageProgress {
        PackageProgress {
            records,
            done: self.digest.is_some(),
            include_history: self.include_history,
            parts: self.next_part,
            bytes: self.bytes,
        }
    }

    /// Extract all complete records from the buffer. The body length is checked against the section limit BEFORE
    /// the body is accumulated, so a declared "giant" size is rejected immediately.
    fn drain(&mut self) -> LR<Vec<PackageRecord>> {
        let mut out = Vec::new();
        loop {
            let b = &self.buf;
            if b.len() < 3 {
                break;
            }
            let section = b[0];
            let l = limits(section)?;
            let id_len = u16::from_be_bytes([b[1], b[2]]) as usize;
            if id_len > ID_MAX {
                return Err(LinkError::Malformed(format!("section {section}: id length {id_len}")));
            }
            if b.len() < 3 + id_len + 4 {
                break;
            }
            let o = 3 + id_len;
            let body_len = u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as usize;
            if body_len > l.body_max {
                return Err(LinkError::Malformed(format!("section {section}: body {body_len} > {}", l.body_max)));
            }
            let total = o + 4 + body_len;
            if b.len() < total {
                break;
            }
            let id = b[3..o].to_vec();
            let body = b[o + 4..total].to_vec();
            check_record(section, &id, &body, self.include_history, &mut self.seen)?;
            self.buf.drain(..total);
            self.records += 1;
            out.push(PackageRecord { section, id, body });
        }
        Ok(out)
    }

    pub fn part(&mut self, pt: &[u8]) -> LR<PackageProgress> {
        let h = self.hash.as_mut().ok_or_else(|| LinkError::Mismatch("package part after END".into()))?;
        let mut r = Rd::new(pt, "package part");
        let idx = r.u32()?;
        if idx != self.next_part {
            return Err(LinkError::Mismatch(format!("package part {idx}, expected {}", self.next_part)));
        }
        let data = r.raw(pt.len() - 4)?;
        if data.is_empty() || data.len() > PACKAGE_CHUNK {
            return Err(LinkError::Malformed(format!("package part size {}", data.len())));
        }
        if self.bytes + data.len() as u64 > PACKAGE_MAX_BYTES {
            return Err(LinkError::Mismatch("package larger than the budget".into()));
        }
        h.update(data);
        self.bytes += data.len() as u64;
        self.next_part += 1;
        self.buf.extend_from_slice(data);
        let recs = self.drain()?;
        Ok(self.progress(recs))
    }

    pub fn end(&mut self, pt: &[u8]) -> LR<PackageProgress> {
        let h = self.hash.take().ok_or_else(|| LinkError::Mismatch("second package END".into()))?;
        let mut r = Rd::new(pt, "package end");
        let parts = r.u32()?;
        let records = r.u64()?;
        let bytes = r.u64()?;
        let want = r.arr::<32>()?;
        r.end()?;
        if !self.buf.is_empty() {
            return Err(LinkError::Mismatch("package ends inside a record".into()));
        }
        let got: [u8; 32] = h.finalize().into();
        if parts != self.next_part || records != self.records || bytes != self.bytes || !ct_eq(&got, &want) {
            return Err(LinkError::Mismatch("package digest or counts differ".into()));
        }
        self.digest = Some(got);
        Ok(self.progress(Vec::new()))
    }

    pub fn digest(&self) -> Option<Vec<u8>> {
        self.digest.map(|d| d.to_vec())
    }
}
