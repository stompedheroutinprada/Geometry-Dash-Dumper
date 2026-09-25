//! Geode "broma" bindings (.bro) parser plus an MSVC x64 layout engine that
//! turns declared members into concrete offsets.

use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct BroFunction {
    pub class: String,
    pub name: String,
    pub signature: String,
    pub is_static: bool,
    pub is_virtual: bool,
    pub win: Option<u32>,
}

#[derive(Clone, Debug)]
pub enum BroMember {
    Field { ty: String, name: String, count: u64 },
    Pad(u64),
}

#[derive(Clone, Debug, Default)]
pub struct BroClass {
    pub name: String,
    pub bases: Vec<String>,
    pub members: Vec<BroMember>,
    pub functions: Vec<BroFunction>,
    pub has_virtuals: bool,
}

#[derive(Default)]
pub struct Bindings {
    pub source: Vec<PathBuf>,
    pub classes: BTreeMap<String, BroClass>,
    /// enum name -> underlying size
    pub enums: HashMap<String, u64>,
}

fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else if b[i] == b'"' {
            // String literal (inline bodies); copy verbatim.
            out.push('"');
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            out.push('"');
            i += 1;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

fn strip_attrs(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("[[") {
        out.push_str(&rest[..i]);
        match rest[i..].find("]]") {
            Some(j) => rest = &rest[i + j + 2..],
            None => {
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

const PLATFORMS: [&str; 9] = ["win", "android", "android32", "android64", "mac", "imac", "m1", "ios", "windows"];

fn is_platform_list(s: &str) -> Option<bool> {
    let parts: Vec<&str> = s.split(',').map(|p| p.trim()).collect();
    if parts.is_empty() || !parts.iter().all(|p| PLATFORMS.contains(p)) {
        return None;
    }
    Some(parts.iter().any(|p| *p == "win" || *p == "windows"))
}

/// Split a class body into statements (`...;` or `... { body }`). Platform
/// blocks (`android, ios { ... }`) are expanded when they include Windows.
fn statements(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inner = String::new();
    let (mut paren, mut brace) = (0i32, 0i32);
    for ch in body.chars() {
        if brace > 0 {
            match ch {
                '{' => brace += 1,
                '}' => {
                    brace -= 1;
                    if brace == 0 {
                        let head = cur.split_whitespace().collect::<Vec<_>>().join(" ");
                        match is_platform_list(&head) {
                            Some(true) => out.extend(statements(&inner)),
                            Some(false) => {}
                            None => out.push(head),
                        }
                        cur.clear();
                        inner.clear();
                        continue;
                    }
                }
                _ => {}
            }
            inner.push(ch);
            continue;
        }
        match ch {
            '(' => paren += 1,
            ')' => paren -= 1,
            '{' if paren == 0 => {
                brace = 1;
                continue;
            }
            ';' if paren == 0 => {
                out.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(ch);
    }
    out.into_iter().map(|s| s.split_whitespace().collect::<Vec<_>>().join(" ")).filter(|s| !s.is_empty()).collect()
}

fn find_top_level(s: &str, needle: char) -> Option<usize> {
    let mut angle = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '<' => angle += 1,
            '>' => angle -= 1,
            c if c == needle && angle == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    u64::from_str_radix(s, 16).ok()
}

/// `win 0x123, imac 0x456` -> value for `win`.
fn platform_value(spec: &str, platform: &str) -> Option<u64> {
    for part in spec.split(',') {
        let mut it = part.split_whitespace();
        if it.next() == Some(platform) {
            return it.next().and_then(parse_hex);
        }
    }
    None
}

impl Bindings {
    pub fn load(path: &Path) -> Result<Bindings> {
        let mut files = Vec::new();
        if path.is_dir() {
            for e in std::fs::read_dir(path)? {
                let p = e?.path();
                if p.extension().is_some_and(|x| x == "bro") || p.file_name().is_some_and(|n| n == "Enums.hpp") {
                    files.push(p);
                }
            }
            files.sort();
        } else {
            files.push(path.to_path_buf());
        }
        let mut b = Bindings::default();
        for f in &files {
            let src = std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
            if f.extension().is_some_and(|x| x == "hpp") {
                b.parse_enums(&src);
            } else {
                b.parse_bro(&src);
            }
        }
        b.source = files;
        Ok(b)
    }

    fn parse_enums(&mut self, src: &str) {
        for line in src.lines() {
            let l = line.trim();
            let Some(rest) = l.strip_prefix("enum ") else { continue };
            let rest = rest.strip_prefix("class ").or_else(|| rest.strip_prefix("struct ")).unwrap_or(rest);
            let (name, under) = match rest.split_once(':') {
                Some((n, u)) => (n.trim(), u.trim().trim_end_matches('{').trim()),
                None => (rest.trim_end_matches('{').trim(), "int"),
            };
            if name.is_empty() || name.contains(' ') {
                continue;
            }
            let size = prim_size(under).map(|p| p.0).unwrap_or(4);
            self.enums.insert(name.to_string(), size);
        }
    }

    pub fn parse_bro(&mut self, src: &str) {
        let src = strip_attrs(&strip_comments(src));
        let mut rest = src.as_str();
        while let Some(i) = rest.find("class ") {
            let at_word = i == 0 || !rest.as_bytes()[i - 1].is_ascii_alphanumeric() && rest.as_bytes()[i - 1] != b'_';
            let after = &rest[i + 6..];
            let Some(open) = after.find('{') else { break };
            let header = &after[..open];
            if !at_word || header.contains(';') {
                rest = &rest[i + 6..];
                continue;
            }
            // Matching close brace.
            let mut depth = 0;
            let mut close = None;
            for (k, c) in after[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(open + k);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(close) = close else { break };
            let body = &after[open + 1..close];
            let (name, bases) = match header.split_once(':').filter(|(a, _)| !a.contains("::") || header.matches(':').count() % 2 == 1) {
                _ => split_header(header),
            };
            let mut cls = BroClass { name: name.clone(), bases, ..Default::default() };
            for st in statements(body) {
                self.parse_statement(&mut cls, &st);
            }
            self.classes.insert(name, cls);
            rest = &after[close + 1..];
        }
    }

    fn parse_statement(&mut self, cls: &mut BroClass, st: &str) {
        if let Some(pad) = st.strip_prefix("PAD") {
            let spec = pad.trim().trim_start_matches('=');
            cls.members.push(BroMember::Pad(platform_value(spec, "win").unwrap_or(0)));
            return;
        }
        if let Some(p) = find_top_level(st, '(') {
            let head = st[..p].trim();
            let name = head.rsplit(|c: char| c == ' ' || c == '*' || c == '&').next().unwrap_or("").to_string();
            let is_static = head.starts_with("static ") || head.contains(" static ");
            let is_virtual = head.starts_with("virtual ") || head.contains(" virtual ");
            cls.has_virtuals |= is_virtual;
            // Address list follows the last `=` after the parameter list.
            let close = matching_paren(st, p).unwrap_or(st.len());
            let tail = &st[close..];
            let win = tail.find('=').and_then(|e| platform_value(&tail[e + 1..], "win")).map(|v| v as u32);
            let signature = st[..close.min(st.len())].trim().to_string();
            cls.functions.push(BroFunction { class: cls.name.clone(), name, signature, is_static, is_virtual, win });
            return;
        }
        // Data member: `Type name;` / `Type name[N];`
        let st = st.trim();
        let (decl, count) = match (st.find('['), st.ends_with(']')) {
            (Some(b), true) => {
                let n = st[b + 1..st.len() - 1].trim();
                let n = n.parse::<u64>().ok().or_else(|| parse_hex(n)).unwrap_or(1);
                (&st[..b], n)
            }
            _ => (st, 1),
        };
        let split = decl.rfind(|c: char| c == ' ' || c == '*' || c == '&');
        let Some(split) = split else { return };
        let name = decl[split + 1..].trim().to_string();
        let ty = decl[..split + 1].trim().to_string();
        if name.is_empty() || ty.is_empty() || ty.contains('=') {
            return;
        }
        cls.members.push(BroMember::Field { ty, name, count });
    }

    pub fn functions(&self) -> impl Iterator<Item = &BroFunction> {
        self.classes.values().flat_map(|c| c.functions.iter())
    }
}

fn matching_paren(s: &str, open: usize) -> Option<usize> {
    let mut depth = 0;
    for (i, c) in s[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_header(header: &str) -> (String, Vec<String>) {
    // `cocos2d::CCNode : cocos2d::CCObject` -> find a ':' that is not part of '::'.
    let b = header.as_bytes();
    let mut split = None;
    for i in 0..b.len() {
        if b[i] == b':' && b.get(i + 1) != Some(&b':') && (i == 0 || b[i - 1] != b':') {
            split = Some(i);
            break;
        }
    }
    match split {
        Some(i) => (
            header[..i].trim().to_string(),
            header[i + 1..].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        ),
        None => (header.trim().to_string(), vec![]),
    }
}

// ---------------------------------------------------------------------------
// Layout engine.

fn prim_size(t: &str) -> Option<(u64, u64)> {
    let t = t.trim();
    let s = match t {
        "bool" | "char" | "signed char" | "unsigned char" | "uint8_t" | "int8_t" | "std::uint8_t" | "std::int8_t" | "byte" | "BYTE"
        | "GLubyte" | "GLboolean" => 1,
        "short" | "unsigned short" | "uint16_t" | "int16_t" | "std::uint16_t" | "std::int16_t" | "wchar_t" | "char16_t" | "GLshort" | "GLushort" => 2,
        "int" | "unsigned" | "unsigned int" | "uint32_t" | "int32_t" | "std::uint32_t" | "std::int32_t" | "float" | "long" | "unsigned long"
        | "GLenum" | "GLint" | "GLuint" | "GLfloat" | "GLsizei" | "char32_t" | "DWORD" => 4,
        "double" | "long long" | "unsigned long long" | "uint64_t" | "int64_t" | "std::uint64_t" | "std::int64_t" | "size_t" | "std::size_t"
        | "intptr_t" | "uintptr_t" | "time_t" | "ptrdiff_t" | "long double" | "cocos2d::ccTime" => 8,
        _ => return None,
    };
    Some((s, s))
}

/// Split template arguments at top level: `A, std::pair<B, C>` -> [A, std::pair<B, C>].
fn template_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur).trim().to_string());
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

#[derive(Clone, Debug)]
pub struct LaidMember {
    pub name: String,
    pub ty: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Layout {
    pub start: u64,
    pub members: Vec<LaidMember>,
    pub end: u64,
    pub align: u64,
    /// Set when a member type could not be sized; members after it are unknown.
    pub error: Option<String>,
}

pub struct LayoutCtx<'a> {
    pub bro: &'a Bindings,
    /// Measured object sizes (from the binary).
    pub measured: &'a dyn Fn(&str) -> Option<u64>,
    /// (base name, mdisp) of RTTI classes, when known from the binary.
    pub rtti_bases: &'a dyn Fn(&str) -> Option<Vec<(String, i32)>>,
    pub cache: std::cell::RefCell<HashMap<String, Option<(u64, u64)>>>,
}

impl<'a> LayoutCtx<'a> {
    pub fn qualify(&self, name: &str) -> Option<String> {
        if self.bro.classes.contains_key(name) {
            return Some(name.to_string());
        }
        for p in ["cocos2d::", "cocos2d::extension::", "geode::"] {
            let q = format!("{p}{name}");
            if self.bro.classes.contains_key(&q) || (self.measured)(&q).is_some() {
                return Some(q);
            }
        }
        None
    }

    /// (size, alignment) of a type as MSVC x64 lays it out.
    pub fn type_size(&self, ty: &str) -> Option<(u64, u64)> {
        let t = ty.trim();
        let t = t.strip_prefix("const ").unwrap_or(t).trim();
        let t = t.strip_suffix(" const").unwrap_or(t).trim();
        if t.ends_with('*') || t.ends_with('&') {
            return Some((8, 8));
        }
        if let Some(p) = prim_size(t) {
            return Some(p);
        }
        let (base, args) = match t.find('<') {
            Some(i) if t.ends_with('>') => (&t[..i], template_args(&t[i + 1..t.len() - 1])),
            _ => (t, vec![]),
        };
        let base = base.trim();
        let tail = base.rsplit("::").next().unwrap_or(base);
        let ns = base.strip_suffix(tail).unwrap_or("");
        let std_like = ns.is_empty() || ns == "gd::" || ns == "std::";
        if std_like {
            match tail {
                "string" => return Some((32, 8)),
                "vector" if args.first().is_some_and(|a| a == "bool") => return Some((32, 8)),
                "vector" => return Some((24, 8)),
                "map" | "set" | "multimap" | "multiset" | "list" => return Some((16, 8)),
                "unordered_map" | "unordered_set" | "unordered_multimap" => return Some((64, 8)),
                "deque" => return Some((40, 8)),
                "function" => return Some((64, 8)),
                "shared_ptr" | "weak_ptr" => return Some((16, 8)),
                "unique_ptr" => return Some((8, 8)),
                "array" if args.len() == 2 => {
                    let (s, a) = self.type_size(&args[0])?;
                    let n = args[1].parse::<u64>().ok().or_else(|| parse_hex(&args[1]))?;
                    return Some((s * n, a));
                }
                "pair" if args.len() == 2 => {
                    let (s1, a1) = self.type_size(&args[0])?;
                    let (s2, a2) = self.type_size(&args[1])?;
                    let a = a1.max(a2);
                    let off2 = align_up(s1, a2);
                    return Some((align_up(off2 + s2, a), a));
                }
                "optional" if args.len() == 1 => {
                    let (s, a) = self.type_size(&args[0])?;
                    return Some((align_up(s + 1, a), a));
                }
                _ => {}
            }
        }
        if base.starts_with("geode::SeedValue") {
            let n = base.trim_start_matches("geode::SeedValue").len() as u64;
            return Some((4 * n.max(1), 4));
        }
        match tail {
            "CCPoint" | "CCSize" | "ccTex2F" | "ccVertex2F" | "ccBlendFunc" => return Some((8, 4)),
            "CCRect" | "ccColor4F" | "ccTexParams" | "ccHSVValue" => return Some((16, 4)),
            "ccVertex3F" => return Some((12, 4)),
            "ccColor3B" => return Some((3, 1)),
            "ccColor4B" => return Some((4, 1)),
            "CCAffineTransform" => return Some((24, 4)),
            "kmMat4" => return Some((64, 4)),
            "kmVec2" => return Some((8, 4)),
            "kmVec3" => return Some((12, 4)),
            "cc_timeval" => return Some((8, 4)),
            "ccV3F_C4B_T2F" | "ccV2F_C4B_T2F_Triangle" => return Some((24, 4)),
            "ccV3F_C4B_T2F_Quad" => return Some((96, 4)),
            "ccV2F_C4B_T2F" => return Some((20, 4)),
            "ccV2F_C4B_T2F_Quad" => return Some((80, 4)),
            "ccColor3F" => return Some((12, 4)),
            _ => {}
        }
        // Pointers to member functions of single-inheritance classes.
        if tail.starts_with("SEL_") {
            return Some((8, 8));
        }
        if let Some(&e) = self.bro.enums.get(tail).or_else(|| self.bro.enums.get(base)) {
            return Some((e, e));
        }
        // A class declared in the bindings or measured in the binary.
        if let Some(q) = self.qualify(base) {
            return self.class_size(&q);
        }
        // Enum-looking names from headers the bindings do not ship; the
        // measured class size catches a wrong guess.
        const SUFFIXES: [&str; 12] =
            ["Type", "State", "Alignment", "Quality", "Mode", "Format", "Result", "Policy", "Direction", "Orientation", "Status", "Kind"];
        let second_upper = tail.chars().nth(1).is_some_and(|c| c.is_ascii_uppercase());
        let enumish = tail.starts_with("FMOD_")
            || ((tail.starts_with('k') || tail.starts_with('t')) && second_upper)
            || tail.starts_with("ccGL")
            || tail.starts_with("tCC")
            || SUFFIXES.iter().any(|x| tail.ends_with(x));
        if enumish && args.is_empty() {
            return Some((4, 4));
        }
        None
    }

    fn class_size(&self, name: &str) -> Option<(u64, u64)> {
        if let Some(c) = self.cache.borrow().get(name) {
            return *c;
        }
        self.cache.borrow_mut().insert(name.to_string(), None);
        let r = match (self.measured)(name) {
            Some(s) => Some((s, 8)),
            None => self.bro.classes.get(name).and_then(|_| {
                let l = self.layout(name);
                if l.error.is_some() { None } else { Some((l.end, l.align)) }
            }),
        };
        self.cache.borrow_mut().insert(name.to_string(), r);
        r
    }

    pub fn layout(&self, name: &str) -> Layout {
        let Some(cls) = self.bro.classes.get(name) else {
            return Layout { start: 0, members: vec![], end: 0, align: 1, error: Some("class not in bindings".into()) };
        };
        let mut align = 1u64;
        let mut error = None;
        // Where the class' own members begin.
        let start = if let Some(mut bases) = (self.rtti_bases)(name).filter(|b| !b.is_empty()) {
            // The bindings sometimes drop a base on purpose and model its vptr
            // as a member; only count bases the bindings declare.
            if !cls.bases.is_empty() && bases.len() > cls.bases.len() {
                let declared: Vec<&str> = cls.bases.iter().map(|b| b.rsplit("::").next().unwrap_or(b)).collect();
                bases.retain(|(b, _)| declared.contains(&b.rsplit("::").next().unwrap_or(b)));
            }
            align = 8;
            let mut end = 0u64;
            for (b, mdisp) in bases {
                let bs = (self.measured)(&b).or_else(|| self.qualify(&b).and_then(|q| self.class_size(&q)).map(|s| s.0));
                match bs {
                    Some(s) => end = end.max(mdisp as u64 + s),
                    None => {
                        // Most unmeasured bases are vptr-only interfaces; the
                        // comparison with the measured class size catches this.
                        end = end.max(mdisp as u64 + 8);
                    }
                }
            }
            end
        } else if !cls.bases.is_empty() {
            let mut end = 0u64;
            for b in &cls.bases {
                let q = self.qualify(b).unwrap_or_else(|| b.clone());
                match self.class_size(&q) {
                    Some((s, a)) => {
                        end = align_up(end, a) + s;
                        align = align.max(a);
                    }
                    None => {
                        error = Some(format!("unknown size of base {b}"));
                    }
                }
            }
            end
        } else if cls.has_virtuals || (self.measured)(name).is_some() && (self.rtti_bases)(name).is_some() {
            align = 8;
            8
        } else {
            0
        };
        let mut cur = start;
        let mut members = Vec::new();
        if error.is_none() {
            for m in &cls.members {
                match m {
                    BroMember::Pad(n) => cur += n,
                    BroMember::Field { ty, name, count } => match self.type_size(ty) {
                        Some((s, a)) => {
                            cur = align_up(cur, a);
                            align = align.max(a);
                            members.push(LaidMember { name: name.clone(), ty: ty.clone(), offset: cur, size: s * count });
                            cur += s * count;
                        }
                        None => {
                            error = Some(format!("unknown type `{ty}` of {name}"));
                            break;
                        }
                    },
                }
            }
        }
        Layout { start, members, end: align_up(cur, align), align, error }
    }
}

fn align_up(v: u64, a: u64) -> u64 {
    if a <= 1 { v } else { v.div_ceil(a) * a }
}

// ---------------------------------------------------------------------------
// Fetching bindings from GitHub.

const REPO_API: &str = "https://api.github.com/repos/geode-sdk/bindings/contents/bindings";
const RAW: &str = "https://raw.githubusercontent.com/geode-sdk/bindings/main/bindings";

fn http_get(url: &str) -> Result<String> {
    let mut resp = ureq::get(url).header("User-Agent", "gddumper").call().with_context(|| format!("GET {url}"))?;
    Ok(resp.body_mut().with_config().limit(64 << 20).read_to_string()?)
}

/// Available binding versions, newest first.
pub fn remote_versions() -> Result<Vec<String>> {
    let body = http_get(REPO_API)?;
    let v: serde_json::Value = serde_json::from_str(&body)?;
    let mut out: Vec<String> = v
        .as_array()
        .context("unexpected GitHub response")?
        .iter()
        .filter(|e| e["type"] == "dir")
        .filter_map(|e| e["name"].as_str().map(String::from))
        .filter(|n| n.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .collect();
    out.sort_by(|a, b| version_key(b).partial_cmp(&version_key(a)).unwrap());
    Ok(out)
}

fn version_key(v: &str) -> f64 {
    // "2.2081" vs "2.208": compare as 2.2081 > 2.208 numerically.
    v.parse::<f64>().unwrap_or(0.0)
}

/// Download one version's .bro files (+ Enums.hpp) into `dir/<version>`.
pub fn fetch_version(version: &str, dir: &Path) -> Result<PathBuf> {
    let out = dir.join(version);
    std::fs::create_dir_all(&out)?;
    for f in ["GeometryDash.bro", "Extras.bro", "Cocos2d.bro"] {
        let dst = out.join(f);
        if dst.exists() {
            continue;
        }
        match http_get(&format!("{RAW}/{version}/{f}")) {
            Ok(body) => std::fs::write(&dst, body)?,
            Err(e) if f != "GeometryDash.bro" => eprintln!("  (skipping {f}: {e})"),
            Err(e) => return Err(e),
        }
    }
    let enums = out.join("Enums.hpp");
    if !enums.exists() {
        if let Ok(body) = http_get(&format!("{RAW}/include/Geode/Enums.hpp")) {
            std::fs::write(&enums, body)?;
        }
    }
    Ok(out)
}
