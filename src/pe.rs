//! Minimal PE32+ loader. The image is mapped by RVA so every other module can
//! read memory exactly as the Windows loader would lay it out.

use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub rva: u32,
    pub vsize: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn contains(&self, rva: u32) -> bool {
        rva >= self.rva && rva < self.rva + self.vsize
    }
    pub fn is_exec(&self) -> bool {
        self.characteristics & SCN_MEM_EXECUTE != 0
    }
    pub fn is_write(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }
}

#[derive(Debug, Clone)]
pub struct Export {
    pub name: Option<String>,
    pub ordinal: u32,
    pub rva: u32,
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    /// RVA of the IAT slot the loader fills with the resolved address.
    pub iat_rva: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeFunction {
    pub begin: u32,
    pub end: u32,
    /// True when the unwind info chains to a parent entry (a split-off
    /// fragment of another function rather than a real entry point).
    pub chained: bool,
}

pub struct Pe {
    pub path: PathBuf,
    pub name: String,
    pub image_base: u64,
    pub image: Vec<u8>,
    pub sections: Vec<Section>,
    pub timestamp: u32,
    pub checksum: u32,
    pub entry: u32,
    pub size_of_image: u32,
    pub exports: Vec<Export>,
    pub imports: Vec<Import>,
    pub runtime_functions: Vec<RuntimeFunction>,
    pub iat_by_rva: HashMap<u32, usize>,
}

fn rd<const N: usize>(d: &[u8], off: usize) -> Result<[u8; N]> {
    d.get(off..off + N)
        .and_then(|s| s.try_into().ok())
        .with_context(|| format!("read out of bounds at {off:#x}"))
}
fn u16_at(d: &[u8], off: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(rd(d, off)?))
}
fn u32_at(d: &[u8], off: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(rd(d, off)?))
}
fn u64_at(d: &[u8], off: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(rd(d, off)?))
}

impl Pe {
    pub fn load(path: &Path) -> Result<Pe> {
        let file = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        if file.get(0..2) != Some(b"MZ") {
            bail!("{} is not a PE file", path.display());
        }
        let pe_off = u32_at(&file, 0x3c)? as usize;
        if file.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
            bail!("bad PE signature");
        }
        let coff = pe_off + 4;
        let machine = u16_at(&file, coff)?;
        if machine != 0x8664 {
            bail!("only x64 images are supported (machine {machine:#x})");
        }
        let nsections = u16_at(&file, coff + 2)? as usize;
        let timestamp = u32_at(&file, coff + 4)?;
        let opt_size = u16_at(&file, coff + 16)? as usize;
        let opt = coff + 20;
        if u16_at(&file, opt)? != 0x20b {
            bail!("not a PE32+ image");
        }
        let entry = u32_at(&file, opt + 16)?;
        let image_base = u64_at(&file, opt + 24)?;
        let size_of_image = u32_at(&file, opt + 56)?;
        let size_of_headers = u32_at(&file, opt + 60)? as usize;
        let checksum = u32_at(&file, opt + 64)?;
        let ndirs = u32_at(&file, opt + 108)? as usize;
        let dir = |i: usize| -> Result<(u32, u32)> {
            if i >= ndirs {
                return Ok((0, 0));
            }
            Ok((u32_at(&file, opt + 112 + i * 8)?, u32_at(&file, opt + 116 + i * 8)?))
        };

        let mut image = vec![0u8; size_of_image as usize];
        let hdr = size_of_headers.min(file.len()).min(image.len());
        image[..hdr].copy_from_slice(&file[..hdr]);

        let mut sections = Vec::with_capacity(nsections);
        let sec_tab = opt + opt_size;
        for i in 0..nsections {
            let s = sec_tab + i * 40;
            let raw_name: [u8; 8] = rd(&file, s)?;
            let name = String::from_utf8_lossy(&raw_name).trim_end_matches('\0').to_string();
            let vsize = u32_at(&file, s + 8)?;
            let rva = u32_at(&file, s + 12)?;
            let raw_size = u32_at(&file, s + 16)? as usize;
            let raw_off = u32_at(&file, s + 20)? as usize;
            let characteristics = u32_at(&file, s + 36)?;
            let n = raw_size.min(vsize.max(raw_size as u32) as usize);
            if raw_off < file.len() {
                let n = n.min(file.len() - raw_off).min(image.len().saturating_sub(rva as usize));
                image[rva as usize..rva as usize + n].copy_from_slice(&file[raw_off..raw_off + n]);
            }
            sections.push(Section { name, rva, vsize: vsize.max(raw_size as u32), characteristics });
        }

        let mut pe = Pe {
            path: path.to_path_buf(),
            name: path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
            image_base,
            image,
            sections,
            timestamp,
            checksum,
            entry,
            size_of_image,
            exports: vec![],
            imports: vec![],
            runtime_functions: vec![],
            iat_by_rva: HashMap::new(),
        };
        let (exp_rva, exp_size) = dir(0)?;
        if exp_rva != 0 {
            pe.exports = pe.parse_exports(exp_rva, exp_size).context("parsing exports")?;
        }
        let (imp_rva, _) = dir(1)?;
        if imp_rva != 0 {
            pe.imports = pe.parse_imports(imp_rva).context("parsing imports")?;
        }
        let (pdata_rva, pdata_size) = dir(3)?;
        if pdata_rva != 0 {
            pe.runtime_functions = pe.parse_pdata(pdata_rva, pdata_size);
        }
        pe.iat_by_rva = pe.imports.iter().enumerate().map(|(i, imp)| (imp.iat_rva, i)).collect();
        Ok(pe)
    }

    pub fn u8(&self, rva: u32) -> Option<u8> {
        self.image.get(rva as usize).copied()
    }
    pub fn u32(&self, rva: u32) -> Option<u32> {
        let r = rva as usize;
        self.image.get(r..r + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }
    pub fn i32(&self, rva: u32) -> Option<i32> {
        self.u32(rva).map(|v| v as i32)
    }
    pub fn u64(&self, rva: u32) -> Option<u64> {
        let r = rva as usize;
        self.image.get(r..r + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }
    pub fn bytes(&self, rva: u32, len: usize) -> &[u8] {
        let s = (rva as usize).min(self.image.len());
        let e = s.saturating_add(len).min(self.image.len());
        &self.image[s..e]
    }
    pub fn cstr(&self, rva: u32) -> Option<String> {
        let s = rva as usize;
        let rest = self.image.get(s..)?;
        let n = rest.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&rest[..n]).into_owned())
    }

    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        let r = va.checked_sub(self.image_base)?;
        (r < self.size_of_image as u64).then_some(r as u32)
    }
    pub fn rva_to_va(&self, rva: u32) -> u64 {
        self.image_base + rva as u64
    }

    pub fn section_of(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains(rva))
    }
    pub fn is_exec(&self, rva: u32) -> bool {
        self.section_of(rva).is_some_and(|s| s.is_exec())
    }
    pub fn exec_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.is_exec())
    }
    /// Initialized, non-executable sections (.rdata, .data, ...).
    pub fn data_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| !s.is_exec() && s.name != ".reloc" && s.name != ".pdata" && s.name != ".rsrc")
    }

    fn parse_exports(&self, rva: u32, size: u32) -> Result<Vec<Export>> {
        let base = self.u32(rva + 16).context("export base")?;
        let nfuncs = self.u32(rva + 20).context("export count")?;
        let nnames = self.u32(rva + 24).context("export names")?;
        let funcs = self.u32(rva + 28).context("export funcs")?;
        let names = self.u32(rva + 32).context("export name table")?;
        let ords = self.u32(rva + 36).context("export ordinals")?;
        let mut name_of: HashMap<u32, String> = HashMap::new();
        for i in 0..nnames {
            let name_rva = self.u32(names + i * 4).context("name rva")?;
            let idx = self.image.get((ords + i * 2) as usize..(ords + i * 2 + 2) as usize).context("ordinal")?;
            let idx = u16::from_le_bytes([idx[0], idx[1]]) as u32;
            name_of.insert(idx, self.cstr(name_rva).unwrap_or_default());
        }
        let mut out = Vec::new();
        for i in 0..nfuncs {
            let f = self.u32(funcs + i * 4).context("func rva")?;
            if f == 0 {
                continue;
            }
            let forwarder = (f >= rva && f < rva + size).then(|| self.cstr(f).unwrap_or_default());
            out.push(Export { name: name_of.remove(&i), ordinal: base + i, rva: f, forwarder });
        }
        Ok(out)
    }

    fn parse_imports(&self, rva: u32) -> Result<Vec<Import>> {
        let mut out = Vec::new();
        let mut d = rva;
        loop {
            let ilt = self.u32(d).context("import descriptor")?;
            let name_rva = self.u32(d + 12).context("import name")?;
            let iat = self.u32(d + 16).context("import iat")?;
            if name_rva == 0 && iat == 0 {
                break;
            }
            let dll = self.cstr(name_rva).unwrap_or_default();
            let lookup = if ilt != 0 { ilt } else { iat };
            let mut i = 0u32;
            loop {
                let entry = self.u64(lookup + i * 8).context("thunk")?;
                if entry == 0 {
                    break;
                }
                let iat_rva = iat + i * 8;
                if entry & (1 << 63) != 0 {
                    out.push(Import { dll: dll.clone(), name: None, ordinal: Some(entry as u16), iat_rva });
                } else {
                    let name = self.cstr(entry as u32 + 2);
                    out.push(Import { dll: dll.clone(), name, ordinal: None, iat_rva });
                }
                i += 1;
            }
            d += 20;
        }
        Ok(out)
    }

    fn parse_pdata(&self, rva: u32, size: u32) -> Vec<RuntimeFunction> {
        let mut out = Vec::with_capacity(size as usize / 12);
        for i in 0..size / 12 {
            let e = rva + i * 12;
            let (Some(begin), Some(end), Some(unwind)) = (self.u32(e), self.u32(e + 4), self.u32(e + 8)) else {
                break;
            };
            if begin == 0 {
                continue;
            }
            // UNWIND_INFO: low 3 bits version, high 5 bits flags; UNW_FLAG_CHAININFO = 4.
            let chained = self.u8(unwind & !1).is_some_and(|b| (b >> 3) & 4 != 0);
            out.push(RuntimeFunction { begin, end, chained });
        }
        out.sort_by_key(|f| f.begin);
        out
    }

    pub fn import_at_iat(&self, iat_rva: u32) -> Option<&Import> {
        self.iat_by_rva.get(&iat_rva).map(|&i| &self.imports[i])
    }
}
