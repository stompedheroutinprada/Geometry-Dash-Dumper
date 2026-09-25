//! MSVC x64 RTTI recovery: type descriptors, complete object locators,
//! class hierarchy descriptors and the vtables that reference them.

use crate::names::demangle_type;
use crate::pe::Pe;
use memchr::memmem;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BaseClass {
    pub name: String,
    /// Offset of the base subobject inside the derived object (PMD.mdisp).
    pub mdisp: i32,
    pub pdisp: i32,
    pub vdisp: i32,
    pub attributes: u32,
    /// Number of bases nested under this entry in the flattened array.
    pub contained: u32,
    pub depth: u32,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Vtable {
    pub rva: u32,
    pub col_rva: u32,
    /// Offset of the subobject this vtable belongs to (COL.offset).
    pub offset: u32,
    pub cd_offset: u32,
    pub entries: Vec<u32>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Class {
    pub name: String,
    pub mangled: String,
    pub td_rva: u32,
    pub chd_rva: Option<u32>,
    pub chd_attributes: u32,
    /// Flattened base class array, excluding the class itself.
    pub all_bases: Vec<BaseClass>,
    /// Direct bases in declaration order.
    pub direct_bases: Vec<BaseClass>,
    pub vtables: Vec<Vtable>,
}

impl Class {
    pub fn primary_vtable(&self) -> Option<&Vtable> {
        self.vtables.iter().find(|v| v.offset == 0)
    }
    pub fn primary_base(&self) -> Option<&BaseClass> {
        self.direct_bases.iter().find(|b| b.mdisp == 0 && b.vdisp == 0 && b.pdisp == -1)
    }
}

pub struct Rtti {
    pub classes: BTreeMap<String, Class>,
    /// vtable rva -> (class name, index in class.vtables)
    pub vtable_owner: HashMap<u32, (String, usize)>,
}

impl Rtti {
    pub fn class(&self, name: &str) -> Option<&Class> {
        self.classes.get(name)
    }
}

pub fn scan(pe: &Pe) -> Rtti {
    // 1. Type descriptors: `{ pVFTable, spare, char name[] }`, name starts ".?AV"/".?AU".
    let mut tds: HashMap<u32, (String, String)> = HashMap::new();
    let mut type_info_vt: HashMap<u64, usize> = HashMap::new();
    for sec in pe.data_sections() {
        let data = pe.bytes(sec.rva, sec.vsize as usize);
        for needle in [&b".?AV"[..], &b".?AU"[..]] {
            for pos in memmem::find_iter(data, needle) {
                let name_rva = sec.rva + pos as u32;
                if name_rva < 16 || (name_rva - 16) % 8 != 0 {
                    continue;
                }
                let td = name_rva - 16;
                let Some(raw) = pe.cstr(name_rva) else { continue };
                if raw.len() < 6 || !raw.ends_with("@@") {
                    continue;
                }
                let vt = pe.u64(td).unwrap_or(0);
                *type_info_vt.entry(vt).or_default() += 1;
                tds.insert(td, (demangle_type(&raw), raw));
            }
        }
    }
    // All genuine descriptors share the type_info vtable pointer.
    if let Some((&common, _)) = type_info_vt.iter().max_by_key(|(_, c)| **c) {
        tds.retain(|td, _| pe.u64(*td) == Some(common));
    }

    // 2. Complete object locators: signature 1, pSelf == own RVA.
    let mut cols: Vec<(u32, u32, u32, u32, u32)> = Vec::new(); // rva, offset, cdOffset, td, chd
    for sec in pe.data_sections() {
        let found: Vec<_> = (0..sec.vsize.saturating_sub(24))
            .into_par_iter()
            .step_by(4)
            .filter_map(|o| {
                let r = sec.rva + o;
                if pe.u32(r)? != 1 || pe.u32(r + 20)? != r {
                    return None;
                }
                let td = pe.u32(r + 12)?;
                if !tds.contains_key(&td) {
                    return None;
                }
                Some((r, pe.u32(r + 4)?, pe.u32(r + 8)?, td, pe.u32(r + 16)?))
            })
            .collect();
        cols.extend(found);
    }
    let col_set: HashMap<u64, usize> = cols.iter().enumerate().map(|(i, c)| (pe.rva_to_va(c.0), i)).collect();

    // 3. Vtables: an 8-aligned pointer to a COL, immediately followed by code pointers.
    let mut vt_hits: Vec<(u32, usize)> = Vec::new();
    for sec in pe.data_sections() {
        let hits: Vec<_> = (0..sec.vsize.saturating_sub(8))
            .into_par_iter()
            .step_by(8)
            .filter_map(|o| {
                let r = sec.rva + o;
                let &i = col_set.get(&pe.u64(r)?)?;
                Some((r + 8, i))
            })
            .collect();
        vt_hits.extend(hits);
    }
    let meta_slots: HashSet<u32> = vt_hits.iter().map(|(v, _)| v - 8).collect();

    let mut classes: BTreeMap<String, Class> = BTreeMap::new();
    let mut by_td: HashMap<u32, String> = HashMap::new();
    for (&td, (name, raw)) in &tds {
        by_td.insert(td, name.clone());
        classes.entry(name.clone()).or_insert_with(|| Class {
            name: name.clone(),
            mangled: raw.clone(),
            td_rva: td,
            chd_rva: None,
            chd_attributes: 0,
            all_bases: vec![],
            direct_bases: vec![],
            vtables: vec![],
        });
    }

    // Hierarchy descriptors.
    for c in &cols {
        let Some(name) = by_td.get(&c.3) else { continue };
        let cls = classes.get_mut(name).unwrap();
        if cls.chd_rva.is_some() {
            continue;
        }
        let chd = c.4;
        let (Some(attrs), Some(nbases), Some(arr)) = (pe.u32(chd + 4), pe.u32(chd + 8), pe.u32(chd + 12)) else {
            continue;
        };
        if nbases == 0 || nbases > 512 {
            continue;
        }
        cls.chd_rva = Some(chd);
        cls.chd_attributes = attrs;
        let mut flat = Vec::new();
        for i in 0..nbases {
            let Some(bcd) = pe.u32(arr + i * 4) else { break };
            let td = pe.u32(bcd).unwrap_or(0);
            let bname = by_td.get(&td).cloned().unwrap_or_else(|| format!("<td {td:#x}>"));
            flat.push(BaseClass {
                name: bname,
                contained: pe.u32(bcd + 4).unwrap_or(0),
                mdisp: pe.i32(bcd + 8).unwrap_or(0),
                pdisp: pe.i32(bcd + 12).unwrap_or(-1),
                vdisp: pe.i32(bcd + 16).unwrap_or(0),
                attributes: pe.u32(bcd + 20).unwrap_or(0),
                depth: 0,
            });
        }
        // Compute depth + direct bases from the pre-order `contained` counts.
        fn walk(flat: &mut [BaseClass], start: usize, end: usize, depth: u32, direct: &mut Vec<usize>) {
            let mut i = start;
            while i < end {
                flat[i].depth = depth;
                if depth == 1 {
                    direct.push(i);
                }
                let n = flat[i].contained as usize;
                let sub_end = (i + 1 + n).min(end);
                walk(flat, i + 1, sub_end, depth + 1, direct);
                i = sub_end;
            }
        }
        let mut direct = Vec::new();
        let len = flat.len();
        walk(&mut flat, 1, len, 1, &mut direct);
        cls.direct_bases = direct.iter().map(|&i| flat[i].clone()).collect();
        cls.all_bases = flat.into_iter().skip(1).collect();
    }

    // Vtable contents.
    for (vt, ci) in vt_hits {
        let c = cols[ci];
        let Some(name) = by_td.get(&c.3) else { continue };
        let mut entries = Vec::new();
        let mut r = vt;
        loop {
            if entries.len() > 0 && meta_slots.contains(&r) {
                break;
            }
            let Some(p) = pe.u64(r) else { break };
            let Some(t) = pe.va_to_rva(p) else { break };
            if !pe.is_exec(t) {
                break;
            }
            entries.push(t);
            r += 8;
            if entries.len() > 4096 {
                break;
            }
        }
        let cls = classes.get_mut(name).unwrap();
        cls.vtables.push(Vtable { rva: vt, col_rva: c.0, offset: c.1, cd_offset: c.2, entries });
    }
    for cls in classes.values_mut() {
        cls.vtables.sort_by_key(|v| (v.offset, v.rva));
    }
    let mut vtable_owner = HashMap::new();
    for cls in classes.values() {
        for (i, v) in cls.vtables.iter().enumerate() {
            vtable_owner.insert(v.rva, (cls.name.clone(), i));
        }
    }
    Rtti { classes, vtable_owner }
}
