// Binary link format: big-endian integers and length-prefixed byte strings.
// Strict parsing: every length is checked before reading; trailing bytes are an error.

use super::{LinkError, LR};

#[derive(Default)]
pub(crate) struct W(pub Vec<u8>);

impl W {
    pub fn new() -> Self {
        W(Vec::new())
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    /// String up to 255 bytes with a 1-byte length.
    pub fn b8(&mut self, b: &[u8]) -> &mut Self {
        assert!(b.len() <= u8::MAX as usize, "b8 overflow");
        self.u8(b.len() as u8).raw(b)
    }
    /// String up to 64 KiB with a 2-byte length.
    pub fn b16(&mut self, b: &[u8]) -> &mut Self {
        assert!(b.len() <= u16::MAX as usize, "b16 overflow");
        self.u16(b.len() as u16).raw(b)
    }
    /// String with a 4-byte length.
    pub fn b32(&mut self, b: &[u8]) -> &mut Self {
        assert!(b.len() <= u32::MAX as usize, "b32 overflow");
        self.u32(b.len() as u32).raw(b)
    }
    pub fn done(self) -> Vec<u8> {
        self.0
    }
}

pub(crate) struct Rd<'a> {
    b: &'a [u8],
    p: usize,
    what: &'static str,
}

impl<'a> Rd<'a> {
    pub fn new(b: &'a [u8], what: &'static str) -> Self {
        Rd { b, p: 0, what }
    }
    fn err(&self, m: &str) -> LinkError {
        LinkError::Malformed(format!("{}: {m} at {}/{}", self.what, self.p, self.b.len()))
    }
    pub fn raw(&mut self, n: usize) -> LR<&'a [u8]> {
        if self.b.len() - self.p < n {
            return Err(self.err(&format!("truncated (need {n})")));
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    pub fn arr<const N: usize>(&mut self) -> LR<[u8; N]> {
        Ok(self.raw(N)?.try_into().expect("length checked"))
    }
    pub fn u8(&mut self) -> LR<u8> {
        Ok(self.raw(1)?[0])
    }
    pub fn u16(&mut self) -> LR<u16> {
        Ok(u16::from_be_bytes(self.arr()?))
    }
    pub fn u32(&mut self) -> LR<u32> {
        Ok(u32::from_be_bytes(self.arr()?))
    }
    pub fn u64(&mut self) -> LR<u64> {
        Ok(u64::from_be_bytes(self.arr()?))
    }
    pub fn b8(&mut self, max: usize) -> LR<&'a [u8]> {
        let n = self.u8()? as usize;
        if n > max {
            return Err(self.err(&format!("field {n} > {max}")));
        }
        self.raw(n)
    }
    pub fn b16(&mut self, max: usize) -> LR<&'a [u8]> {
        let n = self.u16()? as usize;
        if n > max {
            return Err(self.err(&format!("field {n} > {max}")));
        }
        self.raw(n)
    }
    pub fn b32(&mut self, max: usize) -> LR<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(self.err(&format!("field {n} > {max}")));
        }
        self.raw(n)
    }
    pub fn pos(&self) -> usize {
        self.p
    }
    pub fn end(&self) -> LR<()> {
        if self.p != self.b.len() {
            return Err(self.err("trailing bytes"));
        }
        Ok(())
    }
}

/// UTF-8 from field bytes; control characters are forbidden (the name is shown to people).
pub(crate) fn label_from(b: &[u8], what: &str) -> LR<String> {
    let s = std::str::from_utf8(b).map_err(|_| LinkError::Malformed(format!("{what}: not UTF-8")))?;
    if s.chars().any(|c| c.is_control()) {
        return Err(LinkError::Malformed(format!("{what}: control characters")));
    }
    Ok(s.to_string())
}
