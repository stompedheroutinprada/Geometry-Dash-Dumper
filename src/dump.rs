//! Orchestration: load modules, apply names (bindings, signatures, user
//! names), build the program model and derive named layouts.

use crate::bindings::{Bindings, LayoutCtx};
use crate::model::{Module, NameSrc, World};
use crate::names;
use crate::sigs::{self, Kind, Sig, SigResult, Want};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct NamedField {
    pub name: String,
    pub ty: String,
    pub size: u64,
    pub source: NameSrc,
}

#[derive(Clone, Debug)]
pub enum LayoutStatus {
    /// Computed end matches the size measured in the binary.
    Verified { size: u64 },
    Mismatch { computed: u64, measured: u64 },
    Unmeasured { computed: u64 },
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct BindingsMatch {
    pub source: String,
    pub checked: usize,
    pub hits: usize,
    pub applied: bool,
}

pub struct Report {
    pub world: World,
    pub exe: usize,
    /// class -> offset -> names (direct members first, then flattened
    /// members of embedded structs such as `m_gameState.m_cameraZoom`).
    pub named_fields: BTreeMap<String, BTreeMap<i32, Vec<NamedField>>>,
    /// struct -> (container class, member path) for every by-value embedding.
    pub embeds: BTreeMap<String, Vec<(String, String)>>,
    pub layout_status: BTreeMap<String, LayoutStatus>,
    pub named_globals: BTreeMap<(usize, u32), String>,
    pub bindings: Option<BindingsMatch>,
    pub sig_results: Vec<SigResult>,
    pub user_names: usize,
}

pub struct Options {
    pub game_dir: PathBuf,
    pub modules: Vec<String>,
    pub bindings: Option<PathBuf>,
    pub force_bindings: bool,
    pub sigs: Vec<PathBuf>,
    pub names: Vec<PathBuf>,
}

pub fn run(opts: &Options) -> Result<Report> {
    let mut mods = Vec::new();
    for m in &opts.modules {
        let p = opts.game_dir.join(m);
        if !p.exists() {
            eprintln!("warning: {} not found, skipping", p.display());
            continue;
        }
        let t = std::time::Instant::now();
        let md = Module::load(&p).with_context(|| format!("loading {}", p.display()))?;
        eprintln!(
            "[+] {m}: {} classes, {} vtables, {} functions, {} sized classes ({:.2?})",
            md.rtti.classes.len(),
            md.vtable_set.len(),
            md.code.funcs.len(),
            md.sizes.len(),
            t.elapsed()
        );
        mods.push(md);
    }
    anyhow::ensure!(!mods.is_empty(), "no modules loaded from {}", opts.game_dir.display());
    let exe = mods.iter().position(|m| m.pe.name.to_ascii_lowercase().ends_with(".exe")).unwrap_or(0);

    // --- names from bindings
    let bro = match &opts.bindings {
        Some(p) => Some(Bindings::load(p)?),
        None => None,
    };
    let mut bmatch = None;
    if let Some(b) = &bro {
        let m = &mut mods[exe];
        let fns: Vec<_> = b.functions().filter_map(|f| f.win.map(|a| (f, a))).collect();
        let pdata: std::collections::HashSet<u32> = m.pe.runtime_functions.iter().map(|f| f.begin).collect();
        let hits = fns.iter().filter(|(_, a)| m.code.funcs.contains_key(a) || pdata.contains(a)).count();
        let ratio = hits as f64 / fns.len().max(1) as f64;
        if ratio >= 0.85 || opts.force_bindings {
            // Leaf functions only referenced indirectly are not found by the sweep.
            let extra: Vec<u32> = fns.iter().map(|(_, a)| *a).collect();
            let n = m.add_functions(&extra);
            if n > 0 {
                eprintln!("[+] bindings: analysed {n} extra functions");
            }
        }
        let hits = fns.iter().filter(|(_, a)| m.code.funcs.contains_key(a)).count();
        let ratio = hits as f64 / fns.len().max(1) as f64;
        let applied = ratio >= 0.85 || opts.force_bindings;
        eprintln!(
            "[+] bindings: {} classes, {} win addresses, {:.1}% land on function starts{}",
            b.classes.len(),
            fns.len(),
            ratio * 100.0,
            if applied { "" } else { " -> NOT applied (different game version? use --force-bindings)" }
        );
        if applied {
            for (f, a) in &fns {
                if m.code.funcs.contains_key(a) {
                    m.set_name(*a, format!("{}::{}", f.class, f.name), NameSrc::Bindings, f.is_static);
                }
            }
        }
        if applied {
            let n = fill_virtual_gaps(&mut mods, exe, b);
            if n > 0 {
                eprintln!("[+] bindings: named {n} inline virtuals from declaration order");
            }
        }
        bmatch = Some(BindingsMatch {
            source: opts.bindings.as_ref().unwrap().display().to_string(),
            checked: fns.len(),
            hits,
            applied,
        });
    }

    // --- signatures from previous dumps / hand-written files
    let mut all_sigs: Vec<Sig> = Vec::new();
    let mut extras: Vec<sigs::Extra> = Vec::new();
    for p in &opts.sigs {
        let src = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
        all_sigs.extend(sigs::parse(&src).with_context(|| format!("parsing {}", p.display()))?);
        extras.extend(sigs::parse_extra(&src));
    }
    let mut sig_results: Vec<(usize, SigResult)> = Vec::new();
    for (mi, m) in mods.iter().enumerate() {
        let mine: Vec<Sig> = all_sigs.iter().filter(|s| s.module.eq_ignore_ascii_case(&m.pe.name)).cloned().collect();
        if !mine.is_empty() {
            sig_results.extend(sigs::apply(m, &mine).into_iter().map(|r| (mi, r)));
        }
    }
    let mut sig_fields: Vec<(String, i32, String, NameSrc)> = Vec::new();
    let mut named_globals: BTreeMap<(usize, u32), String> = BTreeMap::new();
    if !sig_results.is_empty() {
        let ok = sig_results.iter().filter(|r| r.1.value.is_some()).count();
        eprintln!("[+] signatures: {ok}/{} resolved", sig_results.len());
        for (mi, r) in &sig_results {
            let Some(v) = r.value else { continue };
            match r.sig.kind {
                Kind::Func => {
                    let m = &mut mods[*mi];
                    if m.code.funcs.contains_key(&(v as u32)) {
                        m.set_name(v as u32, r.sig.name.clone(), NameSrc::Signature, false);
                    }
                }
                Kind::Global => {
                    named_globals.insert((*mi, v as u32), r.sig.name.clone());
                }
                Kind::Field => {
                    if let Some((c, f)) = names::split_member(&r.sig.name) {
                        sig_fields.push((c.to_string(), v as i32, f.to_string(), NameSrc::Signature));
                    }
                }
            }
        }
    }

    // Fallback records: vtable slots and field-relative offsets.
    let mut resolved_fields: HashMap<String, i32> =
        sig_fields.iter().map(|(c, o, f, _)| (format!("{c}::{f}"), *o)).collect();
    let mut extra_ok = 0;
    let mut done = vec![false; extras.len()];
    for _pass in 0..6 {
        let before = extra_ok;
        for (i, e) in extras.iter().enumerate() {
        if done[i] {
            continue;
        }
        match e {
            sigs::Extra::VSlot { name, class, vt_off, index } => {
                done[i] = true;
                let m = &mut mods[exe];
                let entry = m.rtti.class(class).and_then(|c| c.vtables.iter().find(|v| v.offset == *vt_off)).and_then(|v| v.entries.get(*index).copied());
                if let Some(e) = entry {
                    let (t, _) = m.resolve_entry(e);
                    if m.entry_import(t).is_none() {
                        m.set_name(t, name.clone(), NameSrc::Signature, false);
                        extra_ok += 1;
                    }
                }
            }
            sigs::Extra::Rel { name, anchor, delta } => {
                if let (Some(&a), Some((c, f))) = (resolved_fields.get(anchor), names::split_member(name)) {
                    let off = a + *delta as i32;
                    sig_fields.push((c.to_string(), off, f.to_string(), NameSrc::Signature));
                    resolved_fields.insert(name.clone(), off);
                    extra_ok += 1;
                    done[i] = true;
                }
            }
            sigs::Extra::RelSub { name, anchor, minus } => {
                if let (Some(&a), Some(&b), Some((c, f))) = (resolved_fields.get(anchor), resolved_fields.get(minus), names::split_member(name)) {
                    sig_fields.push((c.to_string(), a - b, f.to_string(), NameSrc::Signature));
                    resolved_fields.insert(name.clone(), a - b);
                    extra_ok += 1;
                    done[i] = true;
                }
            }
        }
        }
        if extra_ok == before {
            break;
        }
    }
    if !extras.is_empty() {
        eprintln!("[+] fallback records: {extra_ok}/{} resolved (vtable slots / relative fields)", extras.len());
    }

    // --- explicit user names: `func|field|global Name 0xOFFSET`
    let mut user_names = 0;
    for p in &opts.names {
        let src = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
        for line in src.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let Some(v) = parse_num(parts[2]) else { continue };
            user_names += 1;
            match parts[0] {
                "func" | "fn" => mods[exe].set_name(v as u32, parts[1].to_string(), NameSrc::User, false),
                "global" | "data" => {
                    named_globals.insert((exe, v as u32), parts[1].to_string());
                }
                "field" | "member" => {
                    if let Some((c, f)) = names::split_member(parts[1]) {
                        sig_fields.push((c.to_string(), v as i32, f.to_string(), NameSrc::User));
                    }
                }
                _ => user_names -= 1,
            }
        }
    }

    for m in mods.iter_mut() {
        m.compute_ownership();
    }
    let mut world = World::new(mods);
    world.build_fields();

    // Singletons + instance globals get names.
    for (mi, m) in world.modules.iter().enumerate() {
        for s in &m.best_singletons() {
            if let Some(c) = &s.class {
                named_globals.entry((mi, s.global)).or_insert_with(|| format!("{c}::s_instance"));
            }
        }
        for g in &m.instance_globals {
            named_globals.entry((mi, g.global)).or_insert_with(|| format!("{}::s_instance?", g.class));
        }
    }

    // --- named member layouts from the bindings
    let mut named_fields: BTreeMap<String, BTreeMap<i32, Vec<NamedField>>> = BTreeMap::new();
    let mut embeds: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut layout_status = BTreeMap::new();
    if let (Some(b), Some(bm)) = (&bro, &bmatch) {
        let _ = bm;
        // Interfaces without data members (delegates, protocols) are just a vptr.
        fn iface(world: &World, n: &str, depth: u32) -> Option<u64> {
            let c = world.classes.get(n)?;
            if let Some(s) = c.size.or(c.inferred_size) {
                return Some(s);
            }
            if !c.has_chd || depth > 16 {
                return None;
            }
            // Pure interface chain: every base sits at offset 0 and is itself an interface.
            let mut size = 8;
            for b in &c.direct_bases {
                if b.mdisp != 0 {
                    return None;
                }
                size = size.max(iface(world, &b.name, depth + 1)?);
            }
            (size == 8).then_some(8)
        }
        let measured = |n: &str| iface(&world, n, 0);
        let exact = |n: &str| world.classes.get(n).and_then(|c| c.size);
        let rtti_bases = |n: &str| {
            world.classes.get(n).filter(|c| c.module.is_some() || !c.all_bases.is_empty()).map(|c| {
                c.direct_bases.iter().filter(|b| b.pdisp == -1).map(|b| (b.name.clone(), b.mdisp)).collect::<Vec<_>>()
            })
        };
        let ctx = LayoutCtx { bro: b, measured: &measured, rtti_bases: &rtti_bases, cache: Default::default() };
        for name in b.classes.keys() {
            let l = ctx.layout(name);
            if l.members.is_empty() && l.error.is_none() {
                continue;
            }
            let status = match (&l.error, exact(name)) {
                (Some(e), _) => LayoutStatus::Failed(e.clone()),
                (None, Some(s)) if s == l.end => LayoutStatus::Verified { size: s },
                (None, Some(s)) => LayoutStatus::Mismatch { computed: l.end, measured: s },
                (None, None) => LayoutStatus::Unmeasured { computed: l.end },
            };
            let e = named_fields.entry(name.clone()).or_default();
            for mm in &l.members {
                e.entry(mm.offset as i32).or_default().push(NamedField {
                    name: mm.name.clone(),
                    ty: mm.ty.clone(),
                    size: mm.size,
                    source: NameSrc::Bindings,
                });
            }
            layout_status.insert(name.clone(), status);
        }
        // Embedded value structs: expose their members with full paths.
        let direct: Vec<(String, i32, NamedField)> = named_fields
            .iter()
            .flat_map(|(c, m)| m.iter().flat_map(move |(o, v)| v.iter().map(move |f| (c.clone(), *o, f.clone()))))
            .collect();
        for (c, off, f) in direct {
            flatten(&ctx, &mut named_fields, &mut embeds, &c, off, &f.name, &f.ty, 0);
        }
    }
    for (c, off, f, src) in sig_fields {
        let v = named_fields.entry(c).or_default().entry(off).or_default();
        if !v.iter().any(|n| n.name == f) {
            v.push(NamedField { name: f, ty: String::new(), size: 0, source: src });
        }
    }

    // --- name vtable slots that are still anonymous
    for mi in 0..world.modules.len() {
        let mut new_names = Vec::new();
        let m = &world.modules[mi];
        for c in m.rtti.classes.values() {
            for v in &c.vtables {
                for (i, &e) in v.entries.iter().enumerate() {
                    let (t, _) = m.resolve_entry(e);
                    if m.names.get(&t).is_some_and(|n| n.source >= NameSrc::Vtable) || m.entry_import(t).is_some() {
                        continue;
                    }
                    let (n, _) = world.slot_name(mi, &c.name, v.offset, i, e);
                    new_names.push((t, n));
                }
            }
        }
        let m = &mut world.modules[mi];
        for (t, n) in new_names {
            m.set_name(t, n, NameSrc::Vtable, false);
        }
    }

    let sig_results = sig_results.into_iter().map(|r| r.1).collect();
    Ok(Report { world, exe, named_fields, embeds, layout_status, named_globals, bindings: bmatch, sig_results, user_names })
}

#[allow(clippy::too_many_arguments)]
fn flatten(
    ctx: &LayoutCtx,
    out: &mut BTreeMap<String, BTreeMap<i32, Vec<NamedField>>>,
    embeds: &mut BTreeMap<String, Vec<(String, String)>>,
    class: &str,
    base_off: i32,
    path: &str,
    ty: &str,
    depth: u32,
) {
    let t = ty.trim().trim_start_matches("const ").trim();
    if depth > 3 || t.ends_with('*') || t.ends_with('&') || t.contains('<') {
        return;
    }
    let Some(q) = ctx.qualify(t) else { return };
    if ctx.bro.classes.get(&q).is_none_or(|c| c.members.is_empty()) {
        return;
    }
    let l = ctx.layout(&q);
    if l.error.is_some() || l.members.is_empty() {
        return;
    }
    embeds.entry(q.clone()).or_default().push((class.to_string(), path.to_string()));
    for m in &l.members {
        let p = format!("{path}.{}", m.name);
        let off = base_off + m.offset as i32;
        out.entry(class.to_string())
            .or_default()
            .entry(off)
            .or_default()
            .push(NamedField { name: p.clone(), ty: m.ty.clone(), size: m.size, source: NameSrc::Bindings });
        flatten(ctx, out, embeds, class, off, &p, &m.ty, depth + 1);
    }
}

/// Virtuals the bindings declare without a Windows address (`= win inline`)
/// still occupy vtable slots in declaration order. Between two virtuals with
/// known slots, an exact-size gap of unnamed slots is filled in order.
fn fill_virtual_gaps(mods: &mut [Module], exe: usize, b: &Bindings) -> usize {
    let vt_len = |mods: &[Module], class: &str| -> Option<usize> {
        mods.iter().find_map(|m| m.rtti.class(class).and_then(|c| c.primary_vtable()).map(|v| v.entries.len()))
    };
    let mut assign: Vec<(u32, (String, u32, usize), String)> = Vec::new();
    {
        let m = &mods[exe];
        for (cname, bc) in &b.classes {
            let Some(cls) = m.rtti.class(cname) else { continue };
            let Some(vt) = cls.primary_vtable() else { continue };
            let base_len = cls.primary_base().and_then(|pb| vt_len(mods, &pb.name)).unwrap_or(0);
            let targets: Vec<u32> = vt.entries.iter().map(|&e| m.resolve_entry(e).0).collect();
            let _ = base_len;
            let slot_of = |addr: u32| (0..targets.len()).find(|&i| targets[i] == addr);
            // (slot or None, name) for virtuals in declaration order.
            let decls: Vec<(Option<usize>, &str)> = bc
                .functions
                .iter()
                .filter(|f| f.is_virtual && !f.name.starts_with('~'))
                .map(|f| (f.win.and_then(slot_of), f.name.as_str()))
                .collect();
            let mut last: Option<usize> = None;
            let mut pending: Vec<&str> = Vec::new();
            for (slot, name) in decls {
                match slot {
                    Some(s) => {
                        if let Some(l) = last {
                            if !pending.is_empty() && s > l && s - l - 1 == pending.len() {
                                for (k, n) in pending.iter().enumerate() {
                                    let i = l + 1 + k;
                                    assign.push((targets[i], (cname.clone(), 0, i), format!("{cname}::{n}")));
                                }
                            }
                        }
                        last = Some(s);
                        pending.clear();
                    }
                    None if last.is_some() => pending.push(name),
                    None => {}
                }
            }
            // Trailing run up to the end of the vtable.
            if let Some(l) = last {
                if !pending.is_empty() && targets.len() - l - 1 == pending.len() {
                    for (k, n) in pending.iter().enumerate() {
                        let i = l + 1 + k;
                        assign.push((targets[i], (cname.clone(), 0, i), format!("{cname}::{n}")));
                    }
                }
            }
        }
    }
    // Interfaces whose virtuals are all inline: declaration order is the slot order.
    for (cname, bc) in &b.classes {
        let decls: Vec<&str> = bc.functions.iter().filter(|f| f.is_virtual && !f.name.starts_with('~')).map(|f| f.name.as_str()).collect();
        if decls.is_empty() || bc.functions.iter().any(|f| f.is_virtual && f.win.is_some()) {
            continue;
        }
        let mut uniq = decls.clone();
        uniq.sort();
        uniq.dedup();
        if uniq.len() != decls.len() {
            continue; // overloads are reordered by MSVC
        }
        let rtti = mods.iter().find_map(|m| m.rtti.class(cname));
        let Some(rc) = rtti else { continue };
        if !rc.direct_bases.is_empty() && rc.chd_rva.is_some() {
            continue;
        }
        if let Some(v) = rc.primary_vtable() {
            if v.entries.len() != decls.len() {
                continue;
            }
        }
        for (i, n) in decls.iter().enumerate() {
            let key = (cname.clone(), 0, i);
            if !mods[exe].slot_names.contains_key(&key) {
                assign.push((u32::MAX, key, format!("{cname}::{n}")));
            }
        }
    }
    let m = &mut mods[exe];
    let n = assign.len();
    for (t, slot, name) in assign {
        m.slot_names.insert(slot, name.clone());
        if t != u32::MAX && m.entry_import(t).is_none() && m.names.get(&t).is_none_or(|x| x.source < NameSrc::Signature) {
            m.set_name(t, name, NameSrc::Bindings, false);
        }
    }
    n
}

fn parse_num(s: &str) -> Option<i64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => i64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Generate signatures for everything that has a real name in this dump, so
/// the next game update can be dumped with `--sigs` and keep all names.
pub fn make_signatures(r: &Report, include_unverified_fields: bool) -> (Vec<Sig>, Vec<sigs::Extra>, Vec<String>) {
    let nmods = r.world.modules.len();
    let mut wants: Vec<Vec<Want>> = (0..nmods).map(|_| Vec::new()).collect();
    for (mi, m) in r.world.modules.iter().enumerate() {
        let mut seen = HashMap::new();
        let mut funcs: Vec<(&u32, &crate::model::Name)> = m.names.iter().filter(|(_, n)| n.source >= NameSrc::Signature).collect();
        funcs.sort_by_key(|(a, _)| **a);
        for (&rva, n) in funcs {
            if seen.insert(n.name.clone(), rva).is_none() {
                wants[mi].push(Want::Func { name: n.name.clone(), rva });
            }
        }
    }
    for ((mi, g), name) in &r.named_globals {
        wants[*mi].push(Want::Global { name: name.clone(), rva: *g });
    }
    for (cls, fields) in &r.named_fields {
        let fmi = r.world.classes.get(cls).and_then(|c| c.module).unwrap_or(r.exe);
        let ok = match r.layout_status.get(cls) {
            Some(LayoutStatus::Verified { .. }) => true,
            // Plain structs have no measured size; they are recovered through
            // their embedding containers.
            Some(LayoutStatus::Unmeasured { .. }) => include_unverified_fields || r.embeds.contains_key(cls),
            Some(_) => include_unverified_fields,
            None => true,
        };
        if !ok {
            continue;
        }
        let bindings_trusted = r.bindings.as_ref().is_some_and(|b| b.applied);
        for (&off, fs) in fields {
            for f in fs {
                // Layouts from bindings of another build are shown, but not carried forward.
                if f.source == NameSrc::Bindings && !bindings_trusted {
                    continue;
                }
                wants[fmi].push(Want::Field { name: format!("{cls}::{}", f.name), class: cls.clone(), offset: off });
            }
        }
    }
    let mut generated = Vec::new();
    for (mi, w) in wants.iter().enumerate() {
        if !w.is_empty() {
            generated.extend(sigs::generate(&r.world, mi, w));
        }
    }
    let m = &r.world.modules[r.exe];
    let mut ok = Vec::new();
    let mut failed = Vec::new();
    for (name, s) in generated {
        match s {
            Some(s) => ok.push(s),
            None => failed.push(name),
        }
    }
    ok.sort_by(|a, b| (&a.module, a.kind, &a.name).cmp(&(&b.module, b.kind, &b.name)));

    // Fallbacks for what could not get a unique pattern.
    let mut extras = Vec::new();
    let mut still_failed = Vec::new();
    let signed_fields: std::collections::HashSet<&str> = ok.iter().filter(|s| s.kind == Kind::Field).map(|s| s.name.as_str()).collect();
    let mut slot_of: HashMap<u32, (String, u32, usize)> = HashMap::new();
    for c in m.rtti.classes.values() {
        for v in &c.vtables {
            for (i, &e) in v.entries.iter().enumerate() {
                let (t, _) = m.resolve_entry(e);
                let owner_match = m.owner.get(&t).is_some_and(|o| o.class == c.name);
                let cur = slot_of.get(&t);
                if cur.is_none() || (owner_match && cur.is_some_and(|x| x.0 != c.name)) {
                    slot_of.insert(t, (c.name.clone(), v.offset, i));
                }
            }
        }
    }
    let by_name: HashMap<&str, u32> =
        m.names.iter().filter(|(_, n)| n.source >= NameSrc::Signature).map(|(a, n)| (n.name.as_str(), *a)).collect();
    for name in failed {
        if let Some(&rva) = by_name.get(name.as_str()) {
            if let Some((class, vt_off, index)) = slot_of.get(&rva) {
                extras.push(sigs::Extra::VSlot { name, class: class.clone(), vt_off: *vt_off, index: *index });
                continue;
            }
        }
        if let Some((cls, fname)) = names::split_member(&name) {
            // Struct member: recover it from an embedding container.
            if let Some(uses) = r.embeds.get(cls) {
                if let Some((c, path)) = uses.first() {
                    extras.push(sigs::Extra::RelSub { name: name.clone(), anchor: format!("{c}::{path}.{fname}"), minus: format!("{c}::{path}") });
                    continue;
                }
            }
            if let Some(fields) = r.named_fields.get(cls) {
                if let Some(off) = fields.iter().find_map(|(o, v)| v.iter().any(|f| f.name == fname).then_some(*o)) {
                    // Nearest signed field in the same class (prefer the one before).
                    let anchor = fields.range(..off).rev().chain(fields.range(off + 1..)).find_map(|(o, v)| {
                        v.iter().find(|f| signed_fields.contains(format!("{cls}::{}", f.name).as_str())).map(|f| (*o, f))
                    });
                    if let Some((aoff, af)) = anchor {
                        extras.push(sigs::Extra::Rel { name: name.clone(), anchor: format!("{cls}::{}", af.name), delta: (off - aoff) as i64 });
                        continue;
                    }
                }
            }
        }
        still_failed.push(name);
    }
    (ok, extras, still_failed)
}

pub fn default_game_dir() -> Option<PathBuf> {
    let candidates = [
        r"C:\Program Files (x86)\Steam\steamapps\common\Geometry Dash",
        r"C:\Program Files\Steam\steamapps\common\Geometry Dash",
        r"D:\SteamLibrary\steamapps\common\Geometry Dash",
        r"E:\SteamLibrary\steamapps\common\Geometry Dash",
    ];
    candidates.iter().map(PathBuf::from).find(|p| p.join("GeometryDash.exe").exists()).or_else(|| {
        // Parse Steam's libraryfolders.vdf for other libraries.
        let vdf = Path::new(r"C:\Program Files (x86)\Steam\steamapps\libraryfolders.vdf");
        let src = std::fs::read_to_string(vdf).ok()?;
        src.lines()
            .filter_map(|l| l.trim().strip_prefix("\"path\""))
            .map(|p| PathBuf::from(p.trim().trim_matches('"').replace("\\\\", "\\")).join(r"steamapps\common\Geometry Dash"))
            .find(|p| p.join("GeometryDash.exe").exists())
    })
}
