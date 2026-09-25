//! Byte signatures: text format, scanning, and automatic generation.
//!
//! Line format (one signature per line, `#` comments):
//!
//! ```text
//! func   PlayLayer::resetLevel      48 89 5C 24 ?? 57 48 83 EC 20 ...
//! func   PlayLayer::foo             E8 [rel32] 48 8B D8           ; call target
//! field  PlayLayer::m_isPaused      80 BB [u32] 00 74 ?? +0
//! global GameManager::instance      48 8B 0D [rel32] 48 85 C9
//! ```
//!
//! Two fallback record kinds exist for names without a unique pattern:
//!
//! ```text
//! vslot  PlayLayer::checkSnapshot   PlayLayer +0x0 170     ; vtable slot of a class
//! rel    PlayLayer::m_unk36cd       PlayLayer::m_unk36cc +0x1  ; offset from another field
//! ```
//!
//! A `[module.dll]` line switches the module the following records apply to
//! (default: GeometryDash.exe).
//!
//! `??` is a wildcard byte. At most one capture (`[rel32]`, `[u32]`, `[i32]`,
//! `[u16]`, `[u8]`, `[i8]`) may appear; without a capture the result is the
//! match address. A trailing `+N`/`-N` is added to the result (for `rel32`
//! it accounts for bytes between the displacement and the next instruction).

use crate::analysis::Code;
use crate::model::Module;
use anyhow::{Result, bail};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use memchr::memmem;
use rayon::prelude::*;
use std::collections::{BTreeSet, HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Func,
    Field,
    Global,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Func => "func",
            Kind::Field => "field",
            Kind::Global => "global",
        }
    }
    fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "func" | "fn" | "function" => Kind::Func,
            "field" | "member" => Kind::Field,
            "global" | "data" => Kind::Global,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cap {
    Rel32,
    U32,
    I32,
    U16,
    U8,
    I8,
}

impl Cap {
    fn len(self) -> usize {
        match self {
            Cap::Rel32 | Cap::U32 | Cap::I32 => 4,
            Cap::U16 => 2,
            Cap::U8 | Cap::I8 => 1,
        }
    }
    fn token(self) -> &'static str {
        match self {
            Cap::Rel32 => "[rel32]",
            Cap::U32 => "[u32]",
            Cap::I32 => "[i32]",
            Cap::U16 => "[u16]",
            Cap::U8 => "[u8]",
            Cap::I8 => "[i8]",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Sig {
    pub module: String,
    pub kind: Kind,
    pub name: String,
    pub bytes: Vec<Option<u8>>,
    pub capture: Option<(usize, Cap)>,
    pub adjust: i64,
}

impl Sig {
    pub fn to_line(&self) -> String {
        let mut s = String::new();
        let mut i = 0;
        while i < self.bytes.len() {
            if let Some((p, c)) = self.capture {
                if p == i {
                    s.push_str(c.token());
                    s.push(' ');
                    i += c.len();
                    continue;
                }
            }
            match self.bytes[i] {
                Some(b) => s.push_str(&format!("{b:02X} ")),
                None => s.push_str("?? "),
            }
            i += 1;
        }
        let adj = match self.adjust {
            0 => String::new(),
            a if a > 0 => format!(" +{a:#x}"),
            a => format!(" -{:#x}", -a),
        };
        format!("{:<6} {:<48} {}{}", self.kind.label(), self.name, s.trim_end(), adj)
    }
}

pub const DEFAULT_MODULE: &str = "GeometryDash.exe";

pub fn parse(src: &str) -> Result<Vec<Sig>> {
    let mut out = Vec::new();
    let mut module = DEFAULT_MODULE.to_string();
    for (ln, line) in src.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') && !line.contains(' ') {
            module = line[1..line.len() - 1].to_string();
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(k), Some(name)) = (it.next(), it.next()) else { bail!("line {}: expected `<kind> <name> <pattern>`", ln + 1) };
        if k == "vslot" || k == "rel" || k == "relsub" {
            continue;
        }
        let Some(kind) = Kind::parse(k) else { bail!("line {}: unknown kind `{k}`", ln + 1) };
        let mut bytes = Vec::new();
        let mut capture = None;
        let mut adjust = 0i64;
        for tok in it {
            let cap = match tok.to_ascii_lowercase().as_str() {
                "[rel32]" | "[rip]" => Some(Cap::Rel32),
                "[u32]" | "[4]" => Some(Cap::U32),
                "[i32]" => Some(Cap::I32),
                "[u16]" | "[2]" => Some(Cap::U16),
                "[u8]" | "[1]" => Some(Cap::U8),
                "[i8]" => Some(Cap::I8),
                _ => None,
            };
            if let Some(c) = cap {
                if capture.is_some() {
                    bail!("line {}: only one capture allowed", ln + 1);
                }
                capture = Some((bytes.len(), c));
                bytes.extend(std::iter::repeat_n(None, c.len()));
            } else if tok == "?" || tok == "??" {
                bytes.push(None);
            } else if let Some(n) = tok.strip_prefix('+').or_else(|| tok.strip_prefix('-')) {
                let v = parse_num(n).ok_or_else(|| anyhow::anyhow!("line {}: bad offset `{tok}`", ln + 1))?;
                adjust = if tok.starts_with('-') { -v } else { v };
            } else if tok.len() == 2 {
                bytes.push(Some(u8::from_str_radix(tok, 16).map_err(|_| anyhow::anyhow!("line {}: bad byte `{tok}`", ln + 1))?));
            } else {
                bail!("line {}: bad token `{tok}`", ln + 1);
            }
        }
        if bytes.iter().all(|b| b.is_none()) {
            bail!("line {}: pattern has no fixed bytes", ln + 1);
        }
        out.push(Sig { module: module.clone(), kind, name: name.to_string(), bytes, capture, adjust });
    }
    Ok(out)
}

#[derive(Clone, Debug)]
pub enum Extra {
    VSlot { name: String, class: String, vt_off: u32, index: usize },
    Rel { name: String, anchor: String, delta: i64 },
    /// Offset of a struct member = (container.path.member) - (container.path).
    RelSub { name: String, anchor: String, minus: String },
}

impl Extra {
    pub fn to_line(&self) -> String {
        match self {
            Extra::VSlot { name, class, vt_off, index } => format!("vslot  {name:<48} {class} +{vt_off:#x} {index}"),
            Extra::Rel { name, anchor, delta } => {
                let d = if *delta >= 0 { format!("+{delta:#x}") } else { format!("-{:#x}", -delta) };
                format!("rel    {name:<48} {anchor} {d}")
            }
            Extra::RelSub { name, anchor, minus } => format!("relsub {name:<48} {anchor} {minus}"),
        }
    }
}

pub fn parse_extra(src: &str) -> Vec<Extra> {
    let mut out = Vec::new();
    for line in src.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let p: Vec<&str> = line.split_whitespace().collect();
        match p.as_slice() {
            ["vslot", name, class, off, idx] => {
                if let (Some(o), Ok(i)) = (parse_num(off.trim_start_matches('+')), idx.parse()) {
                    out.push(Extra::VSlot { name: name.to_string(), class: class.to_string(), vt_off: o as u32, index: i });
                }
            }
            ["relsub", name, anchor, minus] => {
                out.push(Extra::RelSub { name: name.to_string(), anchor: anchor.to_string(), minus: minus.to_string() });
            }
            ["rel", name, anchor, d] => {
                let v = parse_num(d.trim_start_matches(['+', '-']));
                if let Some(v) = v {
                    let delta = if d.starts_with('-') { -v } else { v };
                    out.push(Extra::Rel { name: name.to_string(), anchor: anchor.to_string(), delta });
                }
            }
            _ => {}
        }
    }
    out
}

fn parse_num(s: &str) -> Option<i64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => i64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Longest run of fixed bytes: (start, len).
fn anchor(bytes: &[Option<u8>]) -> (usize, usize) {
    let (mut best, mut cur_start, mut cur_len) = ((0, 0), 0, 0);
    for (i, b) in bytes.iter().enumerate() {
        if b.is_some() {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best.1 {
                best = (cur_start, cur_len);
            }
        } else {
            cur_len = 0;
        }
    }
    best
}

fn matches_at(hay: &[u8], pos: usize, pat: &[Option<u8>]) -> bool {
    hay.len() >= pos + pat.len() && pat.iter().enumerate().all(|(i, b)| b.is_none_or(|b| hay[pos + i] == b))
}

/// All match RVAs of a pattern in the module's executable sections (up to `limit`).
pub fn scan(m: &Module, pat: &[Option<u8>], limit: usize) -> Vec<u32> {
    let (a, alen) = anchor(pat);
    let needle: Vec<u8> = pat[a..a + alen].iter().map(|b| b.unwrap()).collect();
    let mut out = Vec::new();
    for sec in m.pe.exec_sections() {
        let hay = m.pe.bytes(sec.rva, sec.vsize as usize);
        for p in memmem::find_iter(hay, &needle) {
            if p < a {
                continue;
            }
            let start = p - a;
            if matches_at(hay, start, pat) {
                out.push(sec.rva + start as u32);
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }
    out
}

pub fn resolve(m: &Module, sig: &Sig, at: u32) -> Option<i64> {
    let Some((p, cap)) = sig.capture else { return Some(at as i64 + sig.adjust) };
    let r = at + p as u32;
    let v = match cap {
        Cap::Rel32 => r as i64 + 4 + m.pe.i32(r)? as i64,
        Cap::U32 => m.pe.u32(r)? as i64,
        Cap::I32 => m.pe.i32(r)? as i64,
        Cap::U16 => {
            let b = m.pe.bytes(r, 2);
            u16::from_le_bytes([*b.first()?, *b.get(1)?]) as i64
        }
        Cap::U8 => m.pe.u8(r)? as i64,
        Cap::I8 => m.pe.u8(r)? as i8 as i64,
    };
    Some(v + sig.adjust)
}

#[derive(Clone, Debug)]
pub struct SigResult {
    pub sig: Sig,
    pub value: Option<i64>,
    pub matches: usize,
}

pub fn apply(m: &Module, sigs: &[Sig]) -> Vec<SigResult> {
    sigs.par_iter()
        .map(|s| {
            let hits = scan(m, &s.bytes, 2);
            let value = if hits.len() == 1 { resolve(m, s, hits[0]) } else { None };
            SigResult { sig: s.clone(), value, matches: hits.len() }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Generation.

/// Masked bytes of one instruction: operands likely to change between builds
/// (rip-relative displacements, branch targets, large displacements and
/// immediates) become wildcards.
fn masked(m: &Module, ins: &Instruction, keep_disp: bool) -> Vec<Option<u8>> {
    let rva = (ins.ip() - m.pe.image_base) as u32;
    let raw = m.pe.bytes(rva, ins.len());
    let mut out: Vec<Option<u8>> = raw.iter().map(|b| Some(*b)).collect();
    let mut d = Decoder::with_ip(64, raw, ins.ip(), DecoderOptions::NONE);
    let i2 = d.decode();
    let co = d.get_constant_offsets(&i2);
    let mut wild = |off: usize, size: usize| {
        for k in off..(off + size).min(out.len()) {
            out[k] = None;
        }
    };
    if co.has_displacement() {
        let big = co.displacement_size() >= 4;
        if ins.is_ip_rel_memory_operand() || (big && !keep_disp) {
            wild(co.displacement_offset(), co.displacement_size());
        }
    }
    let is_branch = matches!(ins.flow_control(), FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch);
    if co.has_immediate() {
        let short_branch = is_branch && co.immediate_size() == 1;
        let big = crate::analysis::imm_value(ins).is_some_and(|v| v > 0xff);
        if !short_branch && (is_branch || co.immediate_size() >= 4 || big) {
            wild(co.immediate_offset(), co.immediate_size());
        }
    }
    if co.has_immediate2() {
        wild(co.immediate_offset2(), co.immediate_size2());
    }
    // Near branches encode their target as a rel32 field at the end.
    if is_branch && ins.len() >= 5 && !co.has_immediate() && !ins.is_ip_rel_memory_operand() && ins.op0_kind() == iced_x86::OpKind::NearBranch64 {
        let n = ins.len();
        wild(n - 4, 4);
    }
    out
}

fn decode_from(m: &Module, rva: u32, max: usize) -> Vec<Instruction> {
    let bytes = m.pe.bytes(rva, max);
    let mut d = Decoder::with_ip(64, bytes, m.pe.rva_to_va(rva), DecoderOptions::NONE);
    let mut v = Vec::new();
    while d.can_decode() {
        let i = d.decode();
        if i.is_invalid() {
            break;
        }
        let stop = matches!(i.flow_control(), FlowControl::Return | FlowControl::Interrupt);
        v.push(i);
        if stop {
            break;
        }
    }
    v
}

const MAX_SIG: usize = 96;

/// Grow a pattern instruction-by-instruction until it is unique.
/// `special` lets the caller replace one instruction's bytes (for captures).
fn grow_unique(m: &Module, insns: &[Instruction], special: Option<(usize, Vec<Option<u8>>)>, min_fixed: usize) -> Option<Vec<Option<u8>>> {
    let mut pat: Vec<Option<u8>> = Vec::new();
    let mut cands: Option<Vec<u32>> = None;
    for (k, ins) in insns.iter().enumerate() {
        let part = match &special {
            Some((idx, bytes)) if *idx == k => bytes.clone(),
            _ => masked(m, ins, false),
        };
        pat.extend(part);
        if pat.len() > MAX_SIG {
            return None;
        }
        let fixed = pat.iter().filter(|b| b.is_some()).count();
        if fixed < min_fixed || special.as_ref().is_some_and(|(idx, _)| k < *idx) {
            continue;
        }
        let c = match &cands {
            None => scan(m, &pat, 4096),
            Some(prev) => prev.iter().copied().filter(|&a| matches_at(m.pe.bytes(a, pat.len()), 0, &pat)).collect(),
        };
        if c.len() == 1 {
            return Some(pat);
        }
        if c.is_empty() {
            return None;
        }
        // A capped scan cannot be trusted for filtering later.
        cands = if c.len() >= 4096 { None } else { Some(c) };
    }
    None
}

pub fn func_sig(m: &Module, name: &str, rva: u32) -> Option<Sig> {
    let end = m.func(rva).map(|f| f.end).unwrap_or(rva + 0x200);
    let insns = decode_from(m, rva, ((end - rva) as usize).clamp(16, MAX_SIG + 16));
    if let Some(bytes) = grow_unique(m, &insns, None, 6) {
        return Some(Sig { module: m.pe.name.clone(), kind: Kind::Func, name: name.to_string(), bytes, capture: None, adjust: 0 });
    }
    // Fallback: a unique call site of the function.
    for f in m.code.funcs.values() {
        for c in &f.calls {
            if c.target != crate::analysis::Target::Direct(rva) || c.tail {
                continue;
            }
            let insns = decode_from(m, c.site, MAX_SIG);
            let Some(first) = insns.first() else { continue };
            if first.len() != 5 {
                continue;
            }
            let mut sp = vec![Some(m.pe.u8(c.site)?)];
            sp.extend([None; 4]);
            if let Some(bytes) = grow_unique(m, &insns, Some((0, sp)), 6) {
                return Some(Sig {
                    module: m.pe.name.clone(),
                    kind: Kind::Func,
                    name: name.to_string(),
                    bytes,
                    capture: Some((1, Cap::Rel32)),
                    adjust: 0,
                });
            }
        }
    }
    None
}

/// Signature capturing the displacement of a field access at `site`.
/// `delta` is (field offset - displacement) at that site.
pub fn field_sig(m: &Module, name: &str, site: u32, delta: i64) -> Option<Sig> {
    let insns = decode_from(m, site, MAX_SIG);
    let first = insns.first()?;
    let raw = m.pe.bytes(site, first.len());
    let mut d = Decoder::with_ip(64, raw, first.ip(), DecoderOptions::NONE);
    let i2 = d.decode();
    let co = d.get_constant_offsets(&i2);
    if !co.has_displacement() || first.is_ip_rel_memory_operand() {
        return None;
    }
    let (pos, cap) = match co.displacement_size() {
        4 => (co.displacement_offset(), Cap::I32),
        1 => (co.displacement_offset(), Cap::I8),
        _ => return None,
    };
    let mut sp = masked(m, first, true);
    for k in pos..pos + cap.len() {
        sp[k] = None;
    }
    let bytes = grow_unique(m, &insns, Some((0, sp)), 6)?;
    Some(Sig { module: m.pe.name.clone(), kind: Kind::Field, name: name.to_string(), bytes, capture: Some((pos, cap)), adjust: delta })
}

/// Signature resolving to a global through a rip-relative reference at `site`.
pub fn global_sig(m: &Module, name: &str, site: u32) -> Option<Sig> {
    let insns = decode_from(m, site, MAX_SIG);
    let first = insns.first()?;
    if !first.is_ip_rel_memory_operand() {
        return None;
    }
    let raw = m.pe.bytes(site, first.len());
    let mut d = Decoder::with_ip(64, raw, first.ip(), DecoderOptions::NONE);
    let i2 = d.decode();
    let co = d.get_constant_offsets(&i2);
    let pos = co.displacement_offset();
    let sp = masked(m, first, false);
    let bytes = grow_unique(m, &insns, Some((0, sp)), 5)?;
    // target = next_ip + disp = (site + pos + 4) + disp + (len - pos - 4)
    let adjust = (first.len() - pos - 4) as i64;
    Some(Sig { module: m.pe.name.clone(), kind: Kind::Global, name: name.to_string(), bytes, capture: Some((pos, Cap::Rel32)), adjust })
}

/// Requests for signature generation.
pub enum Want {
    Func { name: String, rva: u32 },
    Field { name: String, class: String, offset: i32 },
    Global { name: String, rva: u32 },
}

pub fn generate(world: &crate::model::World, mi: usize, wants: &[Want]) -> Vec<(String, Option<Sig>)> {
    let m = &world.modules[mi];
    // Index: global rva -> sites; (class, off) -> (site, delta)
    let mut gsites: HashMap<u32, Vec<u32>> = HashMap::new();
    for f in m.code.funcs.values() {
        for r in &f.rip_refs {
            gsites.entry(r.target).or_default().push(r.site);
        }
    }
    let wanted_fields: HashSet<(String, i32)> = wants
        .iter()
        .filter_map(|w| if let Want::Field { class, offset, .. } = w { Some((class.clone(), *offset)) } else { None })
        .collect();
    let mut fsites: HashMap<(String, i32), BTreeSet<(u32, i64)>> = HashMap::new();
    if !wanted_fields.is_empty() {
        for (&fr, o) in &m.owner {
            let Some(f) = m.func(fr) else { continue };
            for a in &f.fields {
                if a.indexed {
                    continue;
                }
                let key = world.resolve_field(&o.class, a.off + o.adj);
                if wanted_fields.contains(&key) {
                    // Displacement at the site is (a.off - this_off_of_register); recover it from the instruction.
                    if let Some(disp) = site_disp(m, a.site) {
                        fsites.entry(key.clone()).or_default().insert((a.site, key.1 as i64 - disp));
                    }
                }
            }
        }
    }
    wants
        .par_iter()
        .map(|w| match w {
            Want::Func { name, rva } => (name.clone(), func_sig(m, name, *rva)),
            Want::Global { name, rva } => {
                let s = gsites.get(rva).and_then(|sites| sites.iter().take(24).find_map(|&s| global_sig(m, name, s)));
                (name.clone(), s)
            }
            Want::Field { name, class, offset } => {
                let s = fsites.get(&(class.clone(), *offset)).and_then(|sites| {
                    sites.iter().take(48).filter_map(|&(site, delta)| field_sig(m, name, site, delta)).min_by_key(|s| s.bytes.len())
                });
                (name.clone(), s)
            }
        })
        .collect()
}

fn site_disp(m: &Module, site: u32) -> Option<i64> {
    let code = Code { pe: &m.pe, vtables: &m.vtable_set, starts: &Default::default(), pdata_end: &Default::default() };
    let ins = code.decode_one(site)?;
    if ins.is_ip_rel_memory_operand() {
        return None;
    }
    let raw = m.pe.bytes(site, ins.len());
    let mut d = Decoder::with_ip(64, raw, ins.ip(), DecoderOptions::NONE);
    let i2 = d.decode();
    let co = d.get_constant_offsets(&i2);
    if !co.has_displacement() || !(co.displacement_size() == 4 || co.displacement_size() == 1) {
        return None;
    }
    Some(ins.memory_displacement64() as i64)
}
