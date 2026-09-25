//! Per-function data-flow analysis on top of iced-x86.
//!
//! Every function is decoded once and a tiny abstract interpreter tracks what
//! each general purpose register holds (`this`, `this + k`, a constant, a
//! fresh heap allocation, a vtable address, ...). From that we collect facts:
//! field accesses relative to `this`, vtable stores (constructors and
//! destructors), allocation sizes, global references and call arguments.

use crate::pe::Pe;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, MemorySize, Mnemonic, OpAccess, OpKind,
    Register,
};
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Largest object offset we are willing to believe.
pub const MAX_OBJ: i64 = 0x80000;
const MAX_ALLOC: u64 = 0x100000;
const VOLATILE: [usize; 7] = [0, 1, 2, 8, 9, 10, 11];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Val {
    Unk,
    /// `this + k`
    This(i32),
    /// Second argument (edx/rdx) as passed on entry.
    Arg1,
    Const(u64),
    /// Address of something in the image (lea reg, [rip+x]).
    Addr(u32),
    /// Value loaded from a global (mov reg, [rip+x]).
    Glob(u32),
    /// Return value of a call that looked like `alloc(size)`, plus offset.
    Alloc(u32, i32),
    /// Pointer loaded from `[this + k]`.
    FieldPtr(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Access {
    Read,
    Write,
    Addr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VType {
    Unknown,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    V128,
    V256,
}

impl VType {
    pub fn from_mem(ms: MemorySize) -> VType {
        match ms {
            MemorySize::Float32 => VType::F32,
            MemorySize::Float64 => VType::F64,
            MemorySize::UInt8 | MemorySize::Int8 => VType::I8,
            MemorySize::UInt16 | MemorySize::Int16 => VType::I16,
            MemorySize::UInt32 | MemorySize::Int32 | MemorySize::DwordOffset => VType::I32,
            MemorySize::UInt64 | MemorySize::Int64 | MemorySize::QwordOffset => VType::I64,
            _ => match ms.size() {
                1 => VType::I8,
                2 => VType::I16,
                4 if ms.is_packed() => VType::F32,
                4 => VType::I32,
                8 => VType::I64,
                16 => VType::V128,
                32 => VType::V256,
                _ => VType::Unknown,
            },
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            VType::Unknown => "?",
            VType::I8 => "i8",
            VType::I16 => "i16",
            VType::I32 => "i32",
            VType::I64 => "i64",
            VType::F32 => "f32",
            VType::F64 => "f64",
            VType::V128 => "v128",
            VType::V256 => "v256",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FieldAccess {
    pub site: u32,
    pub off: i32,
    pub size: u8,
    pub ty: VType,
    pub kind: Access,
    pub indexed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Target {
    Direct(u32),
    Import(u32),
    /// Virtual call through `this`'s own vtable: slot index.
    VirtualThis(u32),
    Indirect,
}

#[derive(Clone, Copy, Debug)]
pub struct CallSite {
    pub site: u32,
    pub target: Target,
    pub rcx: Val,
    pub rdx: Val,
    pub tail: bool,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct RipRef {
    pub site: u32,
    pub target: u32,
    pub kind: Access,
    pub size: u8,
    pub ty: VType,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct VtStore {
    pub site: u32,
    pub vt: u32,
    pub dst: Val,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct GlobalStore {
    pub site: u32,
    pub global: u32,
    pub val: Val,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct Allocation {
    pub site: u32,
    pub size: u64,
    pub allocator: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Trivial {
    Nop,
    ReturnConst(u64),
    Getter { off: i32, size: u8, ty: VType },
    RefGetter { off: i32 },
    Setter { off: i32, size: u8, ty: VType },
    Jump(Target),
    AdjustThunk { delta: i32, target: u32 },
}

#[derive(Clone, Debug, Default)]
pub struct FuncFacts {
    pub start: u32,
    pub end: u32,
    pub insns: u32,
    pub calls: Vec<CallSite>,
    pub rip_refs: Vec<RipRef>,
    pub fields: Vec<FieldAccess>,
    pub vt_stores: Vec<VtStore>,
    pub global_stores: Vec<GlobalStore>,
    pub allocs: Vec<Allocation>,
    pub ptr_fields: Vec<i32>,
    /// Field accesses through a fresh allocation (inlined constructors).
    pub alloc_fields: Vec<(u32, FieldAccess)>,
    pub trivial: Option<Trivial>,
    pub tests_arg_bit: bool,
    /// Incoming rcx is read (or passed on) before being overwritten.
    pub uses_this: bool,
}

fn gpr(r: Register) -> Option<usize> {
    if r == Register::None {
        return None;
    }
    let f = r.full_register();
    let i = (f as u32).wrapping_sub(Register::RAX as u32);
    (i < 16).then_some(i as usize)
}

fn merge(a: Val, b: Val) -> Val {
    if a == b {
        return a;
    }
    match (a, b) {
        (Val::Const(0), x) | (x, Val::Const(0)) if matches!(x, Val::Alloc(..) | Val::This(_)) => x,
        _ => Val::Unk,
    }
}

pub struct Code<'a> {
    pub pe: &'a Pe,
    pub vtables: &'a HashSet<u32>,
    pub starts: &'a BTreeSet<u32>,
    pub pdata_end: &'a HashMap<u32, u32>,
}

impl<'a> Code<'a> {
    fn decoder(&self, rva: u32, len: usize) -> Decoder<'a> {
        let bytes = self.pe.bytes(rva, len);
        Decoder::with_ip(64, bytes, self.pe.rva_to_va(rva), DecoderOptions::NONE)
    }

    pub fn decode_one(&self, rva: u32) -> Option<Instruction> {
        let mut d = self.decoder(rva, 16);
        let ins = d.decode();
        (!ins.is_invalid()).then_some(ins)
    }

    /// If `rva` is `jmp [rip+IAT]` (optionally behind `jmp rel32` stubs),
    /// return the IAT slot.
    pub fn import_thunk(&self, rva: u32) -> Option<u32> {
        let mut cur = rva;
        for _ in 0..3 {
            let ins = self.decode_one(cur)?;
            match ins.flow_control() {
                FlowControl::IndirectBranch if ins.is_ip_rel_memory_operand() => {
                    let slot = self.pe.va_to_rva(ins.ip_rel_memory_address())?;
                    return self.pe.import_at_iat(slot).map(|_| slot);
                }
                FlowControl::UnconditionalBranch => cur = self.pe.va_to_rva(ins.near_branch_target())?,
                _ => return None,
            }
        }
        None
    }

    fn resolve_direct(&self, rva: u32) -> Target {
        match self.import_thunk(rva) {
            Some(slot) => Target::Import(slot),
            None => Target::Direct(rva),
        }
    }

    /// Function extent: .pdata when available, otherwise a linear sweep that
    /// follows forward branches until an unconditional exit.
    pub fn extent(&self, start: u32) -> u32 {
        if let Some(&end) = self.pdata_end.get(&start) {
            return end;
        }
        let next = self.starts.range(start + 1..).next().copied().unwrap_or(u32::MAX);
        let cap = (start + 0x2000).min(next);
        let mut d = self.decoder(start, (cap - start) as usize);
        let base = self.pe.image_base;
        let mut max_t = start;
        let mut ins = Instruction::default();
        while d.can_decode() {
            d.decode_out(&mut ins);
            if ins.is_invalid() {
                return (ins.ip() - base) as u32;
            }
            let next_ip = (ins.next_ip() - base) as u32;
            match ins.flow_control() {
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                    let t = ins.near_branch_target().wrapping_sub(base) as u32;
                    if t > next_ip && t < cap {
                        max_t = max_t.max(t);
                    }
                    if ins.flow_control() == FlowControl::UnconditionalBranch && next_ip > max_t {
                        return next_ip;
                    }
                }
                FlowControl::Return | FlowControl::IndirectBranch | FlowControl::Interrupt | FlowControl::Exception
                    if next_ip > max_t =>
                {
                    return next_ip;
                }
                _ => {}
            }
        }
        cap
    }

    pub fn analyze(&self, start: u32) -> FuncFacts {
        let end = self.extent(start);
        let pe = self.pe;
        let base = pe.image_base;
        let end_va = base + end as u64;
        let mut d = self.decoder(start, (end - start) as usize);
        let mut f = FuncFacts { start, end, ..Default::default() };
        let mut factory = InstructionInfoFactory::new();
        let mut st = [Val::Unk; 16];
        st[1] = Val::This(0);
        st[2] = Val::Arg1;
        let mut pending: HashMap<u64, [Val; 16]> = HashMap::new();
        let mut unreachable = false;
        let mut rcx_written = false;
        let mut small: Vec<Instruction> = Vec::new();
        let mut ins = Instruction::default();

        while d.can_decode() {
            d.decode_out(&mut ins);
            if ins.is_invalid() {
                break;
            }
            f.insns += 1;
            if small.len() < 8 {
                small.push(ins);
            }
            let ip = ins.ip();
            let site = (ip - base) as u32;

            if let Some(p) = pending.remove(&ip) {
                if unreachable {
                    st = p;
                } else {
                    for i in 0..16 {
                        st[i] = merge(st[i], p[i]);
                    }
                }
                unreachable = false;
            } else if unreachable {
                for v in VOLATILE {
                    st[v] = Val::Unk;
                }
                unreachable = false;
            }

            let mnem = ins.mnemonic();
            let info = factory.info(&ins);
            if !rcx_written {
                for u in info.used_registers() {
                    if u.register().full_register() == Register::RCX {
                        match u.access() {
                            OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite => f.uses_this = true,
                            OpAccess::Write | OpAccess::CondWrite => rcx_written = true,
                            _ => {}
                        }
                    }
                }
                let fc = ins.flow_control();
                if !rcx_written
                    && matches!(fc, FlowControl::Call | FlowControl::IndirectCall | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch)
                {
                    let t = ins.near_branch_target();
                    let internal = fc == FlowControl::UnconditionalBranch && t >= base + start as u64 && t < end_va;
                    if !internal {
                        f.uses_this = true;
                    }
                }
            }

            // Global references.
            if ins.is_ip_rel_memory_operand() {
                if let Some(t) = pe.va_to_rva(ins.ip_rel_memory_address()) {
                    let mut kind = Access::Read;
                    if mnem == Mnemonic::Lea {
                        kind = Access::Addr;
                    } else if info.used_memory().iter().any(|m| {
                        m.base() == Register::RIP
                            && matches!(m.access(), OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite)
                    }) {
                        kind = Access::Write;
                    }
                    let ms = ins.memory_size();
                    f.rip_refs.push(RipRef { site, target: t, kind, size: ms.size() as u8, ty: VType::from_mem(ms) });
                }
            }

            // Field accesses through tracked `this`.
            for m in info.used_memory() {
                let Some(b) = gpr(m.base()) else { continue };
                match st[b] {
                    Val::This(o) => {
                        let off = o as i64 + m.displacement() as i64;
                        if (0..MAX_OBJ).contains(&off) {
                            let kind = match m.access() {
                                OpAccess::Write | OpAccess::CondWrite => Access::Write,
                                OpAccess::ReadWrite | OpAccess::ReadCondWrite => Access::Write,
                                _ => Access::Read,
                            };
                            f.fields.push(FieldAccess {
                                site,
                                off: off as i32,
                                size: m.memory_size().size() as u8,
                                ty: VType::from_mem(m.memory_size()),
                                kind,
                                indexed: m.index() != Register::None,
                            });
                        }
                    }
                    Val::Alloc(id, o) => {
                        let off = o as i64 + m.displacement() as i64;
                        if (0..MAX_OBJ).contains(&off) {
                            let kind = match m.access() {
                                OpAccess::Read | OpAccess::CondRead => Access::Read,
                                _ => Access::Write,
                            };
                            f.alloc_fields.push((
                                id,
                                FieldAccess {
                                    site,
                                    off: off as i32,
                                    size: m.memory_size().size() as u8,
                                    ty: VType::from_mem(m.memory_size()),
                                    kind,
                                    indexed: m.index() != Register::None,
                                },
                            ));
                        }
                    }
                    Val::FieldPtr(o) => f.ptr_fields.push(o),
                    _ => {}
                }
            }

            let op0_reg = (ins.op_count() > 0 && ins.op0_kind() == OpKind::Register).then(|| ins.op0_register());
            let dst = op0_reg.and_then(gpr);
            let dst_wide = op0_reg.is_some_and(|r| r.is_gpr64() || r.is_gpr32());
            let dst64 = op0_reg.is_some_and(|r| r.is_gpr64());
            let mut newval: Option<Val> = None;

            match mnem {
                Mnemonic::Mov if dst.is_some() && dst_wide => {
                    newval = Some(match ins.op1_kind() {
                        OpKind::Register => match gpr(ins.op1_register()) {
                            Some(s) if dst64 && ins.op1_register().is_gpr64() => st[s],
                            Some(s) => match st[s] {
                                Val::Const(c) => Val::Const(c & 0xffff_ffff),
                                Val::Arg1 => Val::Arg1,
                                _ => Val::Unk,
                            },
                            None => Val::Unk,
                        },
                        OpKind::Immediate8
                        | OpKind::Immediate16
                        | OpKind::Immediate32
                        | OpKind::Immediate64
                        | OpKind::Immediate8to32
                        | OpKind::Immediate8to64
                        | OpKind::Immediate32to64 => {
                            let v = ins.immediate(1);
                            Val::Const(if dst64 { v } else { v & 0xffff_ffff })
                        }
                        OpKind::Memory if ins.is_ip_rel_memory_operand() && dst64 => {
                            pe.va_to_rva(ins.ip_rel_memory_address()).map(Val::Glob).unwrap_or(Val::Unk)
                        }
                        OpKind::Memory if dst64 && ins.memory_index() == Register::None => {
                            match gpr(ins.memory_base()).map(|b| st[b]) {
                                Some(Val::This(o)) => {
                                    let off = o as i64 + ins.memory_displacement64() as i64;
                                    if (0..MAX_OBJ).contains(&off) { Val::FieldPtr(off as i32) } else { Val::Unk }
                                }
                                _ => Val::Unk,
                            }
                        }
                        _ => Val::Unk,
                    });
                }
                Mnemonic::Lea if dst.is_some() && dst64 => {
                    newval = Some(if ins.is_ip_rel_memory_operand() {
                        pe.va_to_rva(ins.ip_rel_memory_address()).map(Val::Addr).unwrap_or(Val::Unk)
                    } else if ins.memory_index() == Register::None {
                        let disp = ins.memory_displacement64() as i64;
                        match gpr(ins.memory_base()).map(|b| st[b]) {
                            Some(Val::This(o)) => {
                                let off = o as i64 + disp;
                                if disp != 0 && (0..MAX_OBJ).contains(&off) {
                                    f.fields.push(FieldAccess {
                                        site,
                                        off: off as i32,
                                        size: 0,
                                        ty: VType::Unknown,
                                        kind: Access::Addr,
                                        indexed: false,
                                    });
                                }
                                if (-MAX_OBJ..MAX_OBJ).contains(&off) { Val::This(off as i32) } else { Val::Unk }
                            }
                            Some(Val::Alloc(id, o)) => Val::Alloc(id, (o as i64 + disp) as i32),
                            _ => Val::Unk,
                        }
                    } else {
                        Val::Unk
                    });
                }
                Mnemonic::Xor if dst.is_some() && ins.op1_kind() == OpKind::Register && ins.op0_register() == ins.op1_register() => {
                    newval = Some(Val::Const(0));
                }
                Mnemonic::Add | Mnemonic::Sub if dst.is_some() && dst64 && imm_value(&ins).is_some() => {
                    let imm = imm_value(&ins).unwrap() as i64;
                    let imm = if mnem == Mnemonic::Sub { -imm } else { imm };
                    newval = Some(match st[dst.unwrap()] {
                        Val::This(o) if (-MAX_OBJ..MAX_OBJ).contains(&(o as i64 + imm)) => Val::This((o as i64 + imm) as i32),
                        Val::Alloc(id, o) => Val::Alloc(id, (o as i64 + imm) as i32),
                        _ => Val::Unk,
                    });
                }
                Mnemonic::Test | Mnemonic::And if dst.is_some() && ins.op_count() == 2 => {
                    let is_one = imm_value(&ins) == Some(1);
                    if is_one && st[dst.unwrap()] == Val::Arg1 {
                        f.tests_arg_bit = true;
                    }
                }
                _ => {}
            }

            // Stores of tracked values: vtable writes and global writes.
            if mnem == Mnemonic::Mov && ins.op0_kind() == OpKind::Memory && ins.op1_kind() == OpKind::Register && ins.op1_register().is_gpr64() {
                if let Some(s) = gpr(ins.op1_register()) {
                    let src = st[s];
                    if ins.is_ip_rel_memory_operand() {
                        if let Some(g) = pe.va_to_rva(ins.ip_rel_memory_address()) {
                            if matches!(src, Val::Alloc(..) | Val::This(_) | Val::Addr(_)) {
                                f.global_stores.push(GlobalStore { site, global: g, val: src });
                            }
                        }
                    } else if let Val::Addr(v) = src {
                        if self.vtables.contains(&v) && ins.memory_index() == Register::None {
                            let disp = ins.memory_displacement64() as i64;
                            let dstv = match gpr(ins.memory_base()).map(|b| st[b]) {
                                Some(Val::This(o)) => Val::This((o as i64 + disp) as i32),
                                Some(Val::Alloc(id, o)) => Val::Alloc(id, (o as i64 + disp) as i32),
                                _ => Val::Unk,
                            };
                            f.vt_stores.push(VtStore { site, vt: v, dst: dstv });
                        }
                    }
                }
            }

            // Flow control needs the pre-instruction state for call arguments.
            let flow = ins.flow_control();
            let mut call: Option<(Target, bool)> = None;
            match flow {
                FlowControl::Call => {
                    let t = pe.va_to_rva(ins.near_branch_target()).map(|t| self.resolve_direct(t)).unwrap_or(Target::Indirect);
                    call = Some((t, false));
                }
                FlowControl::IndirectCall => {
                    let t = if ins.is_ip_rel_memory_operand() {
                        pe.va_to_rva(ins.ip_rel_memory_address())
                            .filter(|s| pe.import_at_iat(*s).is_some())
                            .map(Target::Import)
                            .unwrap_or(Target::Indirect)
                    } else if ins.op0_kind() == OpKind::Memory && ins.memory_index() == Register::None {
                        match gpr(ins.memory_base()).map(|b| st[b]) {
                            Some(Val::FieldPtr(0)) => Target::VirtualThis((ins.memory_displacement64() / 8) as u32),
                            _ => Target::Indirect,
                        }
                    } else {
                        Target::Indirect
                    };
                    call = Some((t, false));
                }
                FlowControl::UnconditionalBranch => {
                    let t = ins.near_branch_target();
                    if t >= base + start as u64 && t < end_va {
                        if t > ip {
                            let e = pending.entry(t).or_insert(st);
                            for i in 0..16 {
                                e[i] = merge(e[i], st[i]);
                            }
                        }
                    } else if let Some(r) = pe.va_to_rva(t) {
                        call = Some((self.resolve_direct(r), true));
                    }
                }
                FlowControl::IndirectBranch if ins.is_ip_rel_memory_operand() => {
                    if let Some(s) = pe.va_to_rva(ins.ip_rel_memory_address()).filter(|s| pe.import_at_iat(*s).is_some()) {
                        call = Some((Target::Import(s), true));
                    }
                }
                FlowControl::ConditionalBranch => {
                    let t = ins.near_branch_target();
                    if t > ip && t < end_va {
                        match pending.get_mut(&t) {
                            Some(e) => {
                                for i in 0..16 {
                                    e[i] = merge(e[i], st[i]);
                                }
                            }
                            None => {
                                pending.insert(t, st);
                            }
                        }
                    }
                }
                _ => {}
            }

            if let Some((target, tail)) = call {
                f.calls.push(CallSite { site, target, rcx: st[1], rdx: st[2], tail });
                if let Val::FieldPtr(o) = st[1] {
                    f.ptr_fields.push(o);
                }
            }

            // Kill every register the instruction writes.
            for u in info.used_registers() {
                if matches!(u.access(), OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite) {
                    if let Some(i) = gpr(u.register()) {
                        st[i] = Val::Unk;
                    }
                }
            }
            if let (Some(i), Some(v)) = (dst, newval) {
                st[i] = v;
            }

            if let Some((target, tail)) = call {
                // Constructors return `this`: keep tracking the allocation.
                let passthrough = match (target, st[1]) {
                    (Target::Direct(_), Val::Alloc(id, 0)) => Some(id),
                    _ => None,
                };
                let alloc = match (target, st[1]) {
                    _ if tail => None,
                    (Target::Direct(t), Val::Const(n)) if (1..=MAX_ALLOC).contains(&n) => {
                        f.allocs.push(Allocation { site, size: n, allocator: t });
                        Some(f.allocs.len() as u32 - 1)
                    }
                    _ => None,
                };
                for v in VOLATILE {
                    st[v] = Val::Unk;
                }
                if let Some(id) = alloc.or(passthrough) {
                    st[0] = Val::Alloc(id, 0);
                }
            }

            if matches!(
                flow,
                FlowControl::Return | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch | FlowControl::Interrupt | FlowControl::Exception
            ) {
                unreachable = true;
            }
        }

        if f.insns as usize <= small.len() {
            f.trivial = classify_trivial(self, &small);
        }
        f
    }
}

pub fn imm_value(ins: &Instruction) -> Option<u64> {
    (0..ins.op_count()).find_map(|i| match ins.op_kind(i) {
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Some(ins.immediate(i)),
        _ => None,
    })
}

fn arg_reg_index(r: Register) -> Option<u8> {
    // Second argument register in any width, or xmm1.
    match r {
        Register::DL | Register::DX | Register::EDX | Register::RDX => Some(2),
        Register::XMM1 => Some(2),
        _ => None,
    }
}

fn classify_trivial(code: &Code, ins: &[Instruction]) -> Option<Trivial> {
    let pe = code.pe;
    let last = ins.last()?;
    let is_ret = last.flow_control() == FlowControl::Return;
    let base_rcx = |i: &Instruction| i.memory_base() == Register::RCX && i.memory_index() == Register::None;
    match ins.len() {
        1 if is_ret => return Some(Trivial::Nop),
        1 if last.flow_control() == FlowControl::UnconditionalBranch => {
            let t = pe.va_to_rva(last.near_branch_target())?;
            return Some(Trivial::Jump(code.resolve_direct(t)));
        }
        1 if last.flow_control() == FlowControl::IndirectBranch && last.is_ip_rel_memory_operand() => {
            let s = pe.va_to_rva(last.ip_rel_memory_address())?;
            return pe.import_at_iat(s).map(|_| Trivial::Jump(Target::Import(s)));
        }
        2 => {
            let a = &ins[0];
            // this-adjusting thunk: sub/add rcx, imm ; jmp target
            if last.flow_control() == FlowControl::UnconditionalBranch && a.op0_kind() == OpKind::Register && a.op0_register() == Register::RCX {
                let delta = match a.mnemonic() {
                    Mnemonic::Sub => imm_value(a).map(|v| -(v as i64)),
                    Mnemonic::Add => imm_value(a).map(|v| v as i64),
                    Mnemonic::Lea if base_rcx(a) => Some(a.memory_displacement64() as i64),
                    _ => None,
                };
                if let (Some(d), Some(t)) = (delta, pe.va_to_rva(last.near_branch_target())) {
                    return Some(Trivial::AdjustThunk { delta: d as i32, target: t });
                }
            }
            if !is_ret {
                return None;
            }
            match a.mnemonic() {
                Mnemonic::Xor if a.op0_kind() == OpKind::Register && a.op1_kind() == OpKind::Register && a.op0_register() == a.op1_register() => {
                    return Some(Trivial::ReturnConst(0));
                }
                Mnemonic::Mov if a.op0_kind() == OpKind::Register && gpr(a.op0_register()) == Some(0) && imm_value(a).is_some() => {
                    return Some(Trivial::ReturnConst(imm_value(a).unwrap()));
                }
                Mnemonic::Lea if a.op0_register() == Register::RAX && base_rcx(a) => {
                    return Some(Trivial::RefGetter { off: a.memory_displacement64() as i32 });
                }
                _ => {}
            }
            if a.op_count() == 2 && a.op1_kind() == OpKind::Memory && base_rcx(a) && a.op0_kind() == OpKind::Register {
                let r = a.op0_register();
                if gpr(r) == Some(0) || r == Register::XMM0 {
                    let ms = a.memory_size();
                    return Some(Trivial::Getter { off: a.memory_displacement64() as i32, size: ms.size() as u8, ty: VType::from_mem(ms) });
                }
            }
            if a.op_count() == 2 && a.op0_kind() == OpKind::Memory && base_rcx(a) && a.op1_kind() == OpKind::Register && arg_reg_index(a.op1_register()).is_some() {
                let ms = a.memory_size();
                return Some(Trivial::Setter { off: a.memory_displacement64() as i32, size: ms.size() as u8, ty: VType::from_mem(ms) });
            }
            // cmp/setcc style bool getters are 3 instructions; handled below.
        }
        3 | 4 if is_ret => {
            // Struct returned by value: load [rcx+d] -> reg, store reg -> [rdx], mov rax, rdx.
            let a = &ins[0];
            if a.op_count() == 2 && a.op1_kind() == OpKind::Memory && base_rcx(a) && a.op0_kind() == OpKind::Register {
                let stores_to_rdx = ins[1..].iter().any(|i| i.op0_kind() == OpKind::Memory && i.memory_base() == Register::RDX);
                let other_mem = ins[1..].iter().any(|i| i.op_count() > 0 && (0..i.op_count()).any(|k| i.op_kind(k) == OpKind::Memory) && i.memory_base() != Register::RDX);
                if stores_to_rdx && !other_mem {
                    let ms = a.memory_size();
                    return Some(Trivial::Getter { off: a.memory_displacement64() as i32, size: ms.size() as u8, ty: VType::from_mem(ms) });
                }
                // movzx eax, byte [rcx+d] ; <op> ; ret  (e.g. bool getters)
                if gpr(a.op0_register()) == Some(0) && ins.len() == 3 && !ins[1..].iter().any(|i| (0..i.op_count()).any(|k| i.op_kind(k) == OpKind::Memory)) {
                    let ms = a.memory_size();
                    return Some(Trivial::Getter { off: a.memory_displacement64() as i32, size: ms.size() as u8, ty: VType::from_mem(ms) });
                }
            }
        }
        _ => {}
    }
    None
}

/// Whole-module analysis results.
pub struct ModuleCode {
    pub funcs: BTreeMap<u32, FuncFacts>,
    pub thunks: HashMap<u32, u32>,
}

pub fn analyze_module(pe: &Pe, vtables: &HashSet<u32>, extra_starts: &[u32]) -> ModuleCode {
    let mut starts: BTreeSet<u32> = pe.runtime_functions.iter().filter(|f| !f.chained).map(|f| f.begin).collect();
    let pdata_end: HashMap<u32, u32> = pe.runtime_functions.iter().filter(|f| !f.chained).map(|f| (f.begin, f.end)).collect();
    for e in &pe.exports {
        if e.forwarder.is_none() && pe.is_exec(e.rva) {
            starts.insert(e.rva);
        }
    }
    starts.extend(extra_starts.iter().copied().filter(|r| pe.is_exec(*r)));
    if pe.entry != 0 {
        starts.insert(pe.entry);
    }

    let mut funcs: BTreeMap<u32, FuncFacts> = BTreeMap::new();
    let mut todo: Vec<u32> = starts.iter().copied().collect();
    for _round in 0..3 {
        if todo.is_empty() {
            break;
        }
        let code = Code { pe, vtables, starts: &starts, pdata_end: &pdata_end };
        let done: Vec<FuncFacts> = todo.par_iter().map(|&s| code.analyze(s)).collect();
        let mut new_starts = BTreeSet::new();
        for f in done {
            for c in &f.calls {
                if let Target::Direct(t) = c.target {
                    if !starts.contains(&t) && pe.is_exec(t) {
                        new_starts.insert(t);
                    }
                }
            }
            funcs.insert(f.start, f);
        }
        new_starts.retain(|s| !funcs.contains_key(s));
        starts.extend(new_starts.iter().copied());
        todo = new_starts.into_iter().collect();
    }

    let code = Code { pe, vtables, starts: &starts, pdata_end: &pdata_end };
    let thunks = funcs.keys().filter_map(|&s| code.import_thunk(s).map(|i| (s, i))).collect();
    ModuleCode { funcs, thunks }
}
