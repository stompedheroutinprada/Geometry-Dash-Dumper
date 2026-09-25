//! Module- and program-level knowledge built from the per-function facts:
//! allocator/deleter identification, class sizes, constructors/destructors,
//! singletons, method ownership and the aggregated field layout per class.

use crate::analysis::{self, Access, FieldAccess, FuncFacts, ModuleCode, Target, Trivial, VType, Val};
use crate::names;
use crate::pe::Pe;
use crate::rtti::{self, BaseClass, Rtti};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameSrc {
    Inferred,
    Vtable,
    Import,
    Export,
    Signature,
    Bindings,
    User,
}

impl NameSrc {
    pub fn label(self) -> &'static str {
        match self {
            NameSrc::Inferred => "inferred",
            NameSrc::Vtable => "vtable",
            NameSrc::Import => "import",
            NameSrc::Export => "export",
            NameSrc::Signature => "signature",
            NameSrc::Bindings => "bindings",
            NameSrc::User => "user",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Name {
    pub name: String,
    pub source: NameSrc,
    pub is_static: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OwnerSrc {
    Propagated,
    Vtable,
    Structor,
    Named,
}

#[derive(Clone, Debug)]
pub struct Owner {
    pub class: String,
    /// Offset of the `this` the function receives inside `class`.
    pub adj: i32,
    pub source: OwnerSrc,
}

#[derive(Clone, Debug, Default)]
pub struct SizeInfo {
    pub size: u64,
    pub source: &'static str,
    /// Every distinct size observed, with the number of observations.
    pub observed: BTreeMap<u64, (usize, &'static str)>,
}

#[derive(Clone, Debug)]
pub struct Singleton {
    pub class: Option<String>,
    pub global: u32,
    pub accessor: u32,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct InstanceGlobal {
    pub class: String,
    pub global: u32,
    pub func: u32,
}

pub struct Module {
    pub pe: Pe,
    pub rtti: Rtti,
    pub code: ModuleCode,
    pub vtable_set: HashSet<u32>,
    pub allocators: Vec<(u32, usize)>,
    pub deleters: Vec<(Target, usize)>,
    pub sizes: BTreeMap<String, SizeInfo>,
    pub ctors: BTreeMap<u32, String>,
    pub dtors: BTreeMap<u32, String>,
    pub scalar_dtors: BTreeMap<u32, String>,
    pub owner: HashMap<u32, Owner>,
    pub singletons: Vec<Singleton>,
    pub instance_globals: Vec<InstanceGlobal>,
    pub names: HashMap<u32, Name>,
    /// Every name ever attached to an address (identical code folding merges functions).
    pub aliases: HashMap<u32, BTreeSet<String>>,
    /// Names for individual vtable slots: (class, subobject offset, index).
    pub slot_names: HashMap<(String, u32, usize), String>,
    /// Full demangled export signatures by RVA.
    pub export_sigs: HashMap<u32, String>,
}

impl Module {
    pub fn load(path: &Path) -> Result<Module> {
        let pe = Pe::load(path)?;
        let rtti = rtti::scan(&pe);
        let vtable_set: HashSet<u32> = rtti.vtable_owner.keys().copied().collect();
        let extra: Vec<u32> = rtti.classes.values().flat_map(|c| c.vtables.iter().flat_map(|v| v.entries.iter().copied())).collect();
        let code = analysis::analyze_module(&pe, &vtable_set, &extra);
        let mut m = Module {
            pe,
            rtti,
            code,
            vtable_set,
            allocators: vec![],
            deleters: vec![],
            sizes: BTreeMap::new(),
            ctors: BTreeMap::new(),
            dtors: BTreeMap::new(),
            scalar_dtors: BTreeMap::new(),
            owner: HashMap::new(),
            singletons: vec![],
            instance_globals: vec![],
            names: HashMap::new(),
            aliases: HashMap::new(),
            slot_names: HashMap::new(),
            export_sigs: HashMap::new(),
        };
        m.name_exports_imports();
        m.find_structors_and_sizes();
        Ok(m)
    }

    /// One entry per (class, global): the accessor is the function that looks
    /// most like `sharedState()` (by name, then by size) among all functions
    /// that inline the lazy initialisation.
    pub fn best_singletons(&self) -> Vec<Singleton> {
        let mut best: BTreeMap<(Option<String>, u32), (u32, u32, Singleton)> = BTreeMap::new();
        for s in &self.singletons {
            let name = self.names.get(&s.accessor).map(|n| n.name.to_ascii_lowercase()).unwrap_or_default();
            let tail = names::split_member(&name).map(|(_, m)| m.to_string()).unwrap_or_default();
            let rank = if tail.starts_with("shared") || tail == "get" || tail == "instance" || tail.starts_with("getinstance") {
                0
            } else if name.is_empty() {
                1
            } else {
                2
            };
            let size = self.func(s.accessor).map(|f| f.end - f.start).unwrap_or(u32::MAX);
            let e = best.entry((s.class.clone(), s.global)).or_insert((rank, size, s.clone()));
            if (rank, size) < (e.0, e.1) {
                *e = (rank, size, s.clone());
            }
        }
        best.into_values().map(|v| v.2).collect()
    }

    /// Analyse extra entry points (e.g. from bindings) the sweep did not reach.
    pub fn add_functions(&mut self, rvas: &[u32]) -> usize {
        let new: Vec<u32> = rvas.iter().copied().filter(|r| self.pe.is_exec(*r) && !self.code.funcs.contains_key(r)).collect();
        if new.is_empty() {
            return 0;
        }
        let mut starts: BTreeSet<u32> = self.code.funcs.keys().copied().collect();
        starts.extend(new.iter().copied());
        let pdata_end: HashMap<u32, u32> = self.pe.runtime_functions.iter().filter(|f| !f.chained).map(|f| (f.begin, f.end)).collect();
        let code = analysis::Code { pe: &self.pe, vtables: &self.vtable_set, starts: &starts, pdata_end: &pdata_end };
        let facts: Vec<FuncFacts> = new.iter().map(|&s| code.analyze(s)).collect();
        for f in facts {
            if let Some(slot) = code.import_thunk(f.start) {
                self.code.thunks.insert(f.start, slot);
            }
            self.code.funcs.insert(f.start, f);
        }
        new.len()
    }

    pub fn func(&self, rva: u32) -> Option<&FuncFacts> {
        self.code.funcs.get(&rva)
    }

    /// Follow jump stubs and this-adjusting thunks: (final target, this delta).
    pub fn resolve_entry(&self, mut rva: u32) -> (u32, i32) {
        let mut delta = 0;
        for _ in 0..4 {
            match self.func(rva).and_then(|f| f.trivial) {
                Some(Trivial::Jump(Target::Direct(t))) => rva = t,
                Some(Trivial::AdjustThunk { delta: d, target }) => {
                    delta += d;
                    rva = target;
                }
                _ => break,
            }
        }
        (rva, delta)
    }

    pub fn import_name(&self, iat: u32) -> Option<String> {
        let imp = self.pe.import_at_iat(iat)?;
        Some(match &imp.name {
            Some(n) => names::short_function_name(n),
            None => format!("{}#{}", imp.dll, imp.ordinal.unwrap_or(0)),
        })
    }

    /// Name of what a vtable/call entry ultimately points to, if it is an import.
    pub fn entry_import(&self, rva: u32) -> Option<u32> {
        self.code.thunks.get(&rva).copied().or_else(|| match self.func(rva).and_then(|f| f.trivial) {
            Some(Trivial::Jump(Target::Import(s))) => Some(s),
            _ => None,
        })
    }

    pub fn set_name(&mut self, rva: u32, name: String, source: NameSrc, is_static: bool) {
        if source >= NameSrc::Export {
            self.aliases.entry(rva).or_default().insert(name.clone());
        }
        match self.names.get(&rva) {
            Some(n) if n.source > source => {}
            Some(n) if n.source == source && n.name <= name => {}
            _ => {
                self.names.insert(rva, Name { name, source, is_static });
            }
        }
    }

    fn name_exports_imports(&mut self) {
        let exports = self.pe.exports.clone();
        for e in exports {
            let Some(raw) = &e.name else { continue };
            if e.forwarder.is_some() {
                continue;
            }
            let full = names::demangle(raw);
            let is_static = full.contains("static ");
            self.export_sigs.entry(e.rva).or_insert_with(|| full.clone());
            if self.pe.is_exec(e.rva) {
                self.set_name(e.rva, names::short_function_name(raw), NameSrc::Export, is_static);
            }
        }
        let thunks: Vec<(u32, u32)> = self.code.thunks.iter().map(|(a, b)| (*a, *b)).collect();
        for (t, iat) in thunks {
            if let Some(n) = self.import_name(iat) {
                self.set_name(t, format!("{n} (thunk)"), NameSrc::Import, false);
            }
        }
    }

    pub fn class_of_vtable(&self, vt: u32) -> Option<(&str, u32)> {
        let (name, idx) = self.rtti.vtable_owner.get(&vt)?;
        let c = self.rtti.class(name)?;
        Some((name.as_str(), c.vtables[*idx].offset))
    }

    fn is_ancestor(&self, anc: &str, of: &str) -> bool {
        anc == of || self.rtti.class(of).is_some_and(|c| c.all_bases.iter().any(|b| b.name == anc))
    }

    fn find_structors_and_sizes(&mut self) {
        // --- operator delete: called as (this, const size) from functions
        // that test bit 0 of the flags argument (scalar deleting dtors).
        let mut dvotes: HashMap<Target, usize> = HashMap::new();
        let mut entry_set: BTreeSet<u32> = BTreeSet::new();
        for c in self.rtti.classes.values() {
            if let Some(v) = c.primary_vtable() {
                entry_set.extend(v.entries.iter().copied());
            }
        }
        for &e in &entry_set {
            let (t, _) = self.resolve_entry(e);
            let Some(f) = self.func(t) else { continue };
            if !f.tests_arg_bit {
                continue;
            }
            for c in &f.calls {
                if let (Target::Direct(_) | Target::Import(_), Val::This(0), Val::Const(n)) = (c.target, c.rcx, c.rdx) {
                    if (8..=0x100000).contains(&n) {
                        *dvotes.entry(c.target).or_default() += 1;
                    }
                }
            }
        }
        self.deleters = top_votes(dvotes);
        let deleters: HashSet<Target> = self.deleters.iter().map(|d| d.0).collect();

        // --- operator new: its result receives a vtable store.
        let mut avotes: HashMap<u32, usize> = HashMap::new();
        for f in self.code.funcs.values() {
            for vs in &f.vt_stores {
                if let Val::Alloc(id, 0) = vs.dst {
                    *avotes.entry(f.allocs[id as usize].allocator).or_default() += 1;
                }
            }
        }
        self.allocators = top_votes(avotes);
        let allocators: HashSet<u32> = self.allocators.iter().map(|d| d.0).collect();

        let mut observed: BTreeMap<String, BTreeMap<u64, (usize, &'static str)>> = BTreeMap::new();

        // --- scalar deleting destructors + sized delete => exact sizeof.
        let classes: Vec<(String, Vec<u32>)> =
            self.rtti.classes.values().filter_map(|c| c.primary_vtable().map(|v| (c.name.clone(), v.entries.clone()))).collect();
        for (cname, entries) in &classes {
            for &e in entries {
                let (t, delta) = self.resolve_entry(e);
                if delta != 0 {
                    continue;
                }
                let Some(f) = self.code.funcs.get(&t) else { continue };
                if !f.tests_arg_bit {
                    continue;
                }
                let size = f.calls.iter().find_map(|c| match (c.target, c.rcx, c.rdx) {
                    (t, Val::This(0), Val::Const(n)) if deleters.contains(&t) => Some(n),
                    _ => None,
                });
                let Some(size) = size else { continue };
                self.scalar_dtors.insert(t, cname.clone());
                let e = observed.entry(cname.clone()).or_default().entry(size).or_insert((0, "sized delete"));
                e.0 += 1;
                e.1 = "sized delete";
                let inlined = f.vt_stores.iter().any(|v| v.dst == Val::This(0));
                if !inlined {
                    if let Some(d) = f.calls.iter().find_map(|c| match (c.target, c.rcx) {
                        (Target::Direct(d), Val::This(0)) if !deleters.contains(&c.target) => Some(d),
                        _ => None,
                    }) {
                        self.dtors.insert(d, cname.clone());
                    }
                }
                break;
            }
        }

        // --- constructors: functions storing their class' primary vtable into [this].
        let mut ctors = BTreeMap::new();
        for f in self.code.funcs.values() {
            if self.scalar_dtors.contains_key(&f.start) || self.dtors.contains_key(&f.start) {
                continue;
            }
            let prim: Vec<&str> = f
                .vt_stores
                .iter()
                .filter(|v| v.dst == Val::This(0))
                .filter_map(|v| self.class_of_vtable(v.vt).filter(|(_, off)| *off == 0).map(|(n, _)| n))
                .collect();
            let (Some(first), Some(last)) = (prim.first(), prim.last()) else { continue };
            if first != last && self.is_ancestor(last, first) {
                // Most-derived vtable stored first: destructor chain.
                self.dtors.insert(f.start, first.to_string());
            } else {
                ctors.insert(f.start, last.to_string());
            }
        }
        self.ctors = ctors;

        // --- allocations: `new(size)` followed by a vtable store / ctor call.
        let mut singletons = Vec::new();
        for f in self.code.funcs.values() {
            for (id, a) in f.allocs.iter().enumerate() {
                if !allocators.contains(&a.allocator) {
                    continue;
                }
                let id = id as u32;
                let mut cands: Vec<String> = f
                    .vt_stores
                    .iter()
                    .filter(|v| v.dst == Val::Alloc(id, 0))
                    .filter_map(|v| self.class_of_vtable(v.vt).filter(|(_, o)| *o == 0).map(|(n, _)| n.to_string()))
                    .collect();
                for c in &f.calls {
                    if let (Target::Direct(d), Val::Alloc(i, 0)) = (c.target, c.rcx) {
                        if i == id {
                            if let Some(cls) = self.ctors.get(&d) {
                                cands.push(cls.clone());
                            }
                        }
                    }
                }
                let best = cands.iter().max_by_key(|c| self.rtti.class(c).map(|k| k.all_bases.len()).unwrap_or(0)).cloned();
                if let Some(cls) = &best {
                    let e = observed.entry(cls.clone()).or_default().entry(a.size).or_insert((0, "operator new"));
                    e.0 += 1;
                }
                for g in &f.global_stores {
                    if g.val == Val::Alloc(id, 0) {
                        singletons.push(Singleton { class: best.clone(), global: g.global, accessor: f.start, size: a.size });
                    }
                }
            }
        }
        singletons.sort_by_key(|s| (s.class.clone(), s.global, s.accessor));
        singletons.dedup_by_key(|s| (s.class.clone(), s.global, s.accessor));
        self.singletons = singletons;

        for (cls, obs) in observed {
            let pick = obs
                .iter()
                .filter(|(_, (_, src))| *src == "sized delete")
                .max_by_key(|(_, (n, _))| *n)
                .or_else(|| obs.iter().max_by_key(|(_, (n, _))| *n))
                .map(|(s, (_, src))| (*s, *src));
            if let Some((size, source)) = pick {
                self.sizes.insert(cls, SizeInfo { size, source, observed: obs });
            }
        }

        // Structor names.
        let structors: Vec<(u32, String, &str)> = self
            .ctors
            .iter()
            .map(|(a, c)| (*a, c.clone(), "ctor"))
            .chain(self.dtors.iter().map(|(a, c)| (*a, c.clone(), "dtor")))
            .chain(self.scalar_dtors.iter().map(|(a, c)| (*a, c.clone(), "sdtor")))
            .collect();
        for (a, c, kind) in structors {
            let short = names::unqualified(&c).to_string();
            let n = match kind {
                "ctor" => format!("{c}::{short}"),
                "dtor" => format!("{c}::~{short}"),
                _ => format!("{c}::`scalar deleting destructor'"),
            };
            self.set_name(a, n, NameSrc::Inferred, false);
        }
        for (d, _) in self.deleters.clone() {
            if let Target::Direct(d) = d {
                self.set_name(d, "operator delete(void*, size_t)".into(), NameSrc::Inferred, true);
            }
        }
        for (a, _) in self.allocators.clone() {
            self.set_name(a, "operator new(size_t)".into(), NameSrc::Inferred, true);
        }
    }

    /// Assign an owning class (and `this` adjustment) to as many functions as possible.
    pub fn compute_ownership(&mut self) {
        let mut owner: HashMap<u32, Owner> = HashMap::new();
        let put = |owner: &mut HashMap<u32, Owner>, f: u32, o: Owner| match owner.get(&f) {
            Some(old) if old.source >= o.source => {}
            _ => {
                owner.insert(f, o);
            }
        };

        // Vtable slots: the owner is the most-base class whose vtable holds the function.
        let mut holders: HashMap<u32, Vec<(String, i32)>> = HashMap::new();
        for c in self.rtti.classes.values() {
            for v in &c.vtables {
                for &e in &v.entries {
                    if self.entry_import(e).is_some() {
                        continue;
                    }
                    let (t, delta) = self.resolve_entry(e);
                    if self.entry_import(t).is_some() {
                        continue;
                    }
                    holders.entry(t).or_default().push((c.name.clone(), v.offset as i32 + delta));
                }
            }
        }
        for (f, hs) in &holders {
            let f = *f;
            let base = hs.iter().find(|(cand, _)| hs.iter().all(|(other, _)| self.is_ancestor(cand, other)));
            if let Some((cls, adj)) = base {
                put(&mut owner, f, Owner { class: cls.clone(), adj: *adj, source: OwnerSrc::Vtable });
            }
        }

        // Named functions (exports / bindings / signatures). Identical-code-folded
        // functions carry several names; only trust them when the class agrees.
        let mut named: HashMap<u32, BTreeSet<String>> = HashMap::new();
        for (&rva, n) in &self.names {
            if n.is_static || !matches!(n.source, NameSrc::Export | NameSrc::Bindings | NameSrc::Signature | NameSrc::User) {
                continue;
            }
            if let Some((cls, _)) = names::split_member(&n.name) {
                named.entry(rva).or_default().insert(cls.to_string());
            }
        }
        for e in &self.pe.exports {
            if let Some(raw) = &e.name {
                let short = names::short_function_name(raw);
                if let Some((cls, _)) = names::split_member(&short) {
                    if !names::demangle(raw).contains("static ") {
                        named.entry(e.rva).or_default().insert(cls.to_string());
                    }
                }
            }
        }
        for (rva, classes) in named {
            if classes.len() != 1 || !self.code.funcs.contains_key(&rva) || self.code.thunks.contains_key(&rva) {
                continue;
            }
            let cls = classes.into_iter().next().unwrap();
            // Overrides of secondary-base virtuals receive `this` of that subobject.
            let adj = holders.get(&rva).and_then(|hs| hs.iter().find(|(c, _)| *c == cls).map(|h| h.1)).unwrap_or(0);
            put(&mut owner, rva, Owner { class: cls, adj, source: OwnerSrc::Named });
        }
        for (&f, c) in self.ctors.iter().chain(self.dtors.iter()).chain(self.scalar_dtors.iter()) {
            put(&mut owner, f, Owner { class: c.clone(), adj: 0, source: OwnerSrc::Structor });
        }
        // Propagate through calls made with rcx = this (+ base subobject offset).
        let mut skip: HashSet<u32> = self.allocators.iter().map(|a| a.0).collect();
        skip.extend(self.deleters.iter().filter_map(|d| if let Target::Direct(t) = d.0 { Some(t) } else { None }));
        for _round in 0..8 {
            let mut cands: HashMap<u32, Vec<String>> = HashMap::new();
            for (&fr, o) in &owner {
                let Some(f) = self.func(fr) else { continue };
                for c in &f.calls {
                    let (Target::Direct(g), Val::This(k)) = (c.target, c.rcx) else { continue };
                    if skip.contains(&g) || self.code.thunks.contains_key(&g) || !self.code.funcs.get(&g).is_some_and(|f| f.uses_this) {
                        continue;
                    }
                    if self.names.get(&g).is_some_and(|n| n.is_static) {
                        continue;
                    }
                    let at = o.adj + k;
                    let cls = if at == 0 {
                        Some(o.class.clone())
                    } else {
                        self.rtti.class(&o.class).and_then(|c| c.all_bases.iter().find(|b| b.mdisp == at && b.pdisp == -1).map(|b| b.name.clone()))
                    };
                    if let Some(cls) = cls {
                        cands.entry(g).or_default().push(cls);
                    }
                }
            }
            let mut changed = false;
            for (g, cs) in cands {
                if owner.get(&g).is_some_and(|o| o.source > OwnerSrc::Propagated) {
                    continue;
                }
                let Some(lca) = self.common_ancestor(&cs) else { continue };
                if owner.get(&g).map(|o| &o.class) != Some(&lca) {
                    owner.insert(g, Owner { class: lca, adj: 0, source: OwnerSrc::Propagated });
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        // Globals that receive `this` from an owned method.
        let mut inst = Vec::new();
        for (&fr, o) in &owner {
            let Some(f) = self.func(fr) else { continue };
            for g in &f.global_stores {
                if g.val == Val::This(-o.adj) && self.pe.section_of(g.global).is_some_and(|s| s.is_write()) {
                    inst.push(InstanceGlobal { class: o.class.clone(), global: g.global, func: fr });
                }
            }
        }
        inst.sort_by_key(|i| (i.class.clone(), i.global, i.func));
        inst.dedup_by_key(|i| (i.class.clone(), i.global));
        self.instance_globals = inst;
        self.owner = owner;
    }

    /// Most-derived class that is a zero-offset ancestor-or-self of every candidate.
    fn common_ancestor(&self, cands: &[String]) -> Option<String> {
        let chain = |c: &str| -> Vec<String> {
            let mut v = vec![c.to_string()];
            if let Some(k) = self.rtti.class(c) {
                v.extend(k.all_bases.iter().filter(|b| b.mdisp == 0 && b.pdisp == -1).map(|b| b.name.clone()));
            }
            v
        };
        let first = chain(&cands[0]);
        let common: Vec<String> = first.into_iter().filter(|a| cands[1..].iter().all(|c| chain(c).contains(a))).collect();
        common.into_iter().max_by_key(|c| self.rtti.class(c).map(|k| k.all_bases.len()).unwrap_or(0))
    }
}

fn top_votes<K: Copy + Ord>(votes: HashMap<K, usize>) -> Vec<(K, usize)> {
    let max = votes.values().copied().max().unwrap_or(0);
    let mut v: Vec<(K, usize)> = votes.into_iter().filter(|(_, n)| *n >= 3 && *n * 4 >= max).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v
}

// ---------------------------------------------------------------------------
// Program-wide view across modules.

#[derive(Clone, Debug, Default)]
pub struct FieldStat {
    pub reads: u32,
    pub writes: u32,
    pub addr: u32,
    pub sizes: BTreeSet<u8>,
    pub types: BTreeSet<VType>,
    pub ptr: bool,
    pub indexed: bool,
    pub funcs: BTreeSet<(usize, u32)>,
    pub getters: BTreeSet<String>,
    pub setters: BTreeSet<String>,
}

impl FieldStat {
    pub fn type_hint(&self) -> String {
        if self.ptr {
            return "ptr".into();
        }
        let t: Vec<&str> = self.types.iter().filter(|t| **t != VType::Unknown).map(|t| t.label()).collect();
        if t.is_empty() {
            if self.addr > 0 {
                return "obj".into();
            }
            return "?".into();
        }
        t.join("|")
    }
}

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct ClassView {
    pub name: String,
    pub module: Option<usize>,
    pub direct_bases: Vec<BaseClass>,
    pub all_bases: Vec<BaseClass>,
    pub size: Option<u64>,
    /// Upper bound from the gap to the next base in some derived class.
    pub inferred_size: Option<u64>,
    /// Hierarchy descriptor seen in some module (bases are authoritative).
    pub has_chd: bool,
    pub vptr_offsets: BTreeSet<i32>,
}

pub struct World {
    pub modules: Vec<Module>,
    pub classes: BTreeMap<String, ClassView>,
    pub fields: BTreeMap<String, BTreeMap<i32, FieldStat>>,
}

impl World {
    pub fn new(modules: Vec<Module>) -> World {
        let mut classes: BTreeMap<String, ClassView> = BTreeMap::new();
        for (mi, m) in modules.iter().enumerate() {
            for c in m.rtti.classes.values() {
                let v = classes.entry(c.name.clone()).or_insert_with(|| ClassView { name: c.name.clone(), ..Default::default() });
                if !c.vtables.is_empty() && v.module.is_none() {
                    v.module = Some(mi);
                }
                v.has_chd |= c.chd_rva.is_some();
                if v.all_bases.len() < c.all_bases.len() {
                    v.direct_bases = c.direct_bases.clone();
                    v.all_bases = c.all_bases.clone();
                }
                for vt in &c.vtables {
                    v.vptr_offsets.insert(vt.offset as i32);
                }
                if let Some(s) = m.sizes.get(&c.name) {
                    if v.size.is_none() || s.source == "sized delete" {
                        v.size = Some(s.size);
                    }
                }
            }
        }
        let mut gaps: HashMap<String, u64> = HashMap::new();
        for v in classes.values() {
            let mut bases: Vec<&BaseClass> = v.direct_bases.iter().filter(|b| b.pdisp == -1).collect();
            bases.sort_by_key(|b| b.mdisp);
            for w in bases.windows(2) {
                let g = (w[1].mdisp - w[0].mdisp) as u64;
                let e = gaps.entry(w[0].name.clone()).or_insert(g);
                *e = (*e).min(g);
            }
        }
        for (n, g) in gaps {
            if let Some(v) = classes.get_mut(&n) {
                v.inferred_size = Some(g);
            }
        }
        World { modules, classes, fields: BTreeMap::new() }
    }

    pub fn size_of(&self, c: &str) -> Option<u64> {
        self.classes.get(c).and_then(|v| v.size)
    }

    /// Map `(class, offset)` to the class that actually declares that offset.
    pub fn resolve_field(&self, class: &str, off: i32) -> (String, i32) {
        let mut cls = class.to_string();
        let mut off = off;
        for _ in 0..64 {
            let Some(v) = self.classes.get(&cls) else { break };
            let mut bases: Vec<&BaseClass> = v.direct_bases.iter().filter(|b| b.pdisp == -1).collect();
            bases.sort_by_key(|b| b.mdisp);
            let mut next = None;
            for (i, b) in bases.iter().enumerate() {
                let bsize = self.size_of(&b.name).or_else(|| self.classes.get(&b.name).and_then(|c| c.inferred_size));
                let upper = bsize
                    .map(|s| b.mdisp as i64 + s as i64)
                    .or_else(|| bases.get(i + 1).map(|n| n.mdisp as i64))
                    .or_else(|| if b.mdisp > 0 { Some(b.mdisp as i64 + 8) } else { None });
                if let Some(u) = upper {
                    if (b.mdisp as i64) <= off as i64 && (off as i64) < u {
                        next = Some((b.name.clone(), off - b.mdisp));
                        break;
                    }
                }
            }
            match next {
                Some((b, o)) => {
                    cls = b;
                    off = o;
                }
                None => break,
            }
        }
        (cls, off)
    }

    fn add_access(&mut self, mi: usize, func: u32, class: &str, off: i32, a: &FieldAccess, ptr: bool) {
        let (cls, o) = self.resolve_field(class, off);
        if self.classes.get(&cls).is_some_and(|v| v.vptr_offsets.contains(&o)) && (a.size == 8 || a.size == 0) {
            return;
        }
        let st = self.fields.entry(cls).or_default().entry(o).or_default();
        match a.kind {
            Access::Read => st.reads += 1,
            Access::Write => st.writes += 1,
            Access::Addr => st.addr += 1,
        }
        if a.size > 0 {
            st.sizes.insert(a.size);
        }
        st.types.insert(a.ty);
        st.ptr |= ptr;
        st.indexed |= a.indexed;
        st.funcs.insert((mi, func));
    }

    pub fn build_fields(&mut self) {
        let mut todo: Vec<(usize, u32, String, i32, FieldAccess, bool)> = Vec::new();
        let mut accessors: Vec<(String, i32, String, bool)> = Vec::new();
        for (mi, m) in self.modules.iter().enumerate() {
            for (&fr, o) in &m.owner {
                let Some(f) = m.func(fr).filter(|f| f.uses_this) else { continue };
                let ptrs: HashSet<i32> = f.ptr_fields.iter().copied().collect();
                for a in &f.fields {
                    let off = a.off + o.adj;
                    todo.push((mi, fr, o.class.clone(), off, *a, a.size == 8 && ptrs.contains(&a.off)));
                }
                // Named trivial getters/setters give the field a name hint.
                let alias = m.aliases.get(&fr).and_then(|a| {
                    a.iter().filter_map(|n| names::split_member(n)).find(|(c, _)| *c == o.class).map(|(_, meth)| meth.to_string())
                });
                if let (Some(t), Some(method)) = (f.trivial, alias) {
                    {
                        match t {
                            Trivial::Getter { off, .. } | Trivial::RefGetter { off } => accessors.push((o.class.clone(), off + o.adj, method, false)),
                            Trivial::Setter { off, .. } => accessors.push((o.class.clone(), off + o.adj, method, true)),
                            _ => {}
                        }
                    }
                }
            }
            // Inlined constructors inside create()-style functions.
            for f in m.code.funcs.values() {
                for (id, a) in &f.alloc_fields {
                    let cls = f
                        .vt_stores
                        .iter()
                        .filter(|v| v.dst == Val::Alloc(*id, 0))
                        .filter_map(|v| m.class_of_vtable(v.vt).filter(|(_, o)| *o == 0).map(|(n, _)| n.to_string()))
                        .last();
                    if let Some(cls) = cls {
                        todo.push((mi, f.start, cls, a.off, *a, false));
                    }
                }
            }
        }
        for (mi, fr, cls, off, a, ptr) in todo {
            self.add_access(mi, fr, &cls, off, &a, ptr);
        }
        for (cls, off, method, setter) in accessors {
            let (c, o) = self.resolve_field(&cls, off);
            let st = self.fields.entry(c).or_default().entry(o).or_default();
            if setter {
                st.setters.insert(method);
            } else {
                st.getters.insert(method);
            }
        }
    }

    pub fn is_ancestor(&self, anc: &str, of: &str) -> bool {
        anc == of || self.classes.get(of).is_some_and(|c| c.all_bases.iter().any(|b| b.name == anc))
    }

    /// Class chain at subobject `off` of `class`, most-derived first.
    pub fn chain_at(&self, class: &str, off: u32) -> Vec<String> {
        let mut out = Vec::new();
        let Some(v) = self.classes.get(class) else { return out };
        if off == 0 {
            out.push(class.to_string());
        }
        let mut bs: Vec<&BaseClass> = v.all_bases.iter().filter(|b| b.mdisp as u32 == off && b.pdisp == -1).collect();
        bs.sort_by_key(|b| b.depth);
        out.extend(bs.iter().map(|b| b.name.clone()));
        out
    }

    /// Primary vtable (module index, entries) of a class anywhere in the program.
    pub fn primary_vtable(&self, class: &str) -> Option<(usize, &[u32])> {
        let mi = self.classes.get(class)?.module?;
        let c = self.modules[mi].rtti.class(class)?;
        c.primary_vtable().map(|v| (mi, v.entries.as_slice()))
    }

    /// Names at `rva` (all folded aliases) that belong to `class` or one of its ancestors.
    fn name_for_class(&self, m: &Module, rva: u32, class: &str) -> Option<String> {
        let mut cands: Vec<&String> = m.aliases.get(&rva).map(|a| a.iter().collect()).unwrap_or_default();
        if let Some(n) = m.names.get(&rva).filter(|n| n.source >= NameSrc::Export) {
            cands.push(&n.name);
        }
        // Prefer the most-derived owner.
        cands
            .into_iter()
            .filter_map(|n| names::split_member(n).map(|(o, _)| (o.to_string(), n)))
            .filter(|(o, _)| self.is_ancestor(o, class))
            .max_by_key(|(o, _)| self.classes.get(o).map(|c| c.all_bases.len()).unwrap_or(0))
            .map(|(_, n)| n.clone())
    }

    /// Name every vtable slot using the whole hierarchy (cocos exports,
    /// bindings of base classes, ...). Returns (slot name, inherited-from).
    pub fn slot_name(&self, mi: usize, class: &str, vt_off: u32, slot: usize, entry: u32) -> (String, Option<String>) {
        let m = &self.modules[mi];
        let short = names::unqualified(class).to_string();
        let (target, _) = m.resolve_entry(entry);
        if let Some(n) = m.slot_names.get(&(class.to_string(), vt_off, slot)) {
            return (n.clone(), None);
        }
        if m.scalar_dtors.contains_key(&target) {
            return (format!("{class}::~{short}"), None);
        }
        if let Some(iat) = m.entry_import(entry).or_else(|| m.entry_import(target)) {
            let n = m.import_name(iat).unwrap_or_default();
            return (n.clone(), names::split_member(&n).map(|(c, _)| c.to_string()));
        }
        if let Some(n) = self.name_for_class(m, target, class) {
            let owner = names::split_member(&n).map(|(c, _)| c.to_string());
            return match owner {
                Some(o) if o != class => (n, Some(o)),
                _ => (n, None),
            };
        }
        // Method name for this slot from any class in the chain that knows it.
        let mut method: Option<String> = None;
        for c in self.chain_at(class, vt_off) {
            if let Some(n) = self.modules.iter().find_map(|mm| mm.slot_names.get(&(c.clone(), 0, slot))) {
                method = names::split_member(n).map(|(_, x)| x.to_string());
                break;
            }
            let Some((bmi, entries)) = self.primary_vtable(&c) else { continue };
            let Some(&be) = entries.get(slot) else { continue };
            let bm = &self.modules[bmi];
            let (bt, _) = bm.resolve_entry(be);
            let known = self.name_for_class(bm, bt, &c).or_else(|| bm.entry_import(be).and_then(|s| bm.import_name(s)));
            if let Some(n) = known {
                if let Some((_, meth)) = names::split_member(&n) {
                    method = Some(meth.to_string());
                    break;
                }
            }
        }
        let folded = m.names.get(&target).filter(|n| n.source >= NameSrc::Export).map(|n| n.name.clone());
        let owner = m.owner.get(&target).map(|o| o.class.clone()).filter(|c| c != class && self.is_ancestor(c, class));
        let meth = method.unwrap_or_else(|| format!("vfunc_{slot}"));
        match (owner, folded) {
            (Some(o), _) => (format!("{o}::{meth}"), Some(o)),
            (None, Some(f)) => (format!("{class}::{meth} (code shared with {f})"), None),
            (None, None) => (format!("{class}::{meth}"), None),
        }
    }
}
