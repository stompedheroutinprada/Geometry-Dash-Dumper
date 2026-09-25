//! Orchestration: load modules, apply names (signatures, user names) and
//! build the program model.

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

pub struct Report {
    pub world: World,
    pub exe: usize,
    /// class -> offset -> names.
    pub named_fields: BTreeMap<String, BTreeMap<i32, Vec<NamedField>>>,
    pub named_globals: BTreeMap<(usize, u32), String>,
    pub sig_results: Vec<SigResult>,
    pub user_names: usize,
}

pub struct Options {
    pub game_dir: PathBuf,
    pub modules: Vec<String>,
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
                    m.add_functions(&[v as u32]);
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
                "func" | "fn" => {
                    mods[exe].add_functions(&[v as u32]);
                    mods[exe].set_name(v as u32, parts[1].to_string(), NameSrc::User, false)
                }
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

    let mut named_fields: BTreeMap<String, BTreeMap<i32, Vec<NamedField>>> = BTreeMap::new();
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
    Ok(Report { world, exe, named_fields, named_globals, sig_results, user_names })
}

fn parse_num(s: &str) -> Option<i64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => i64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Generate signatures for everything that has a real name in this dump, so
/// the next game update can be dumped with `--sigs` and keep all names.
pub fn make_signatures(r: &Report) -> (Vec<Sig>, Vec<sigs::Extra>, Vec<String>) {
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
        for (&off, fs) in fields {
            for f in fs {
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
