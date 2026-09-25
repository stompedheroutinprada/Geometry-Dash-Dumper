//! MSVC name demangling helpers.

use msvc_demangler::DemangleFlags;

/// Demangle a full MSVC symbol (e.g. an export). Falls back to the raw name.
pub fn demangle(sym: &str) -> String {
    if !sym.starts_with('?') {
        return sym.to_string();
    }
    msvc_demangler::demangle(sym, DemangleFlags::llvm()).unwrap_or_else(|_| sym.to_string())
}

/// Qualified function name without return type / calling convention / params,
/// e.g. `?init@CCNode@cocos2d@@UEAA_NXZ` -> `cocos2d::CCNode::init`.
pub fn short_function_name(sym: &str) -> String {
    if !sym.starts_with('?') {
        return sym.to_string();
    }
    if let Ok(s) = msvc_demangler::demangle(sym, DemangleFlags::NAME_ONLY) {
        return s;
    }
    // Hand-rolled fallback for simple `?name@Scope@Scope@@...` symbols.
    let body = &sym[1..];
    let end = body.find("@@").unwrap_or(body.len());
    let mut parts: Vec<&str> = body[..end].split('@').collect();
    parts.reverse();
    parts.join("::")
}

/// Demangle an RTTI type descriptor name like `.?AVCCNode@cocos2d@@`.
pub fn demangle_type(raw: &str) -> String {
    let rest = raw.strip_prefix(".?AV").or_else(|| raw.strip_prefix(".?AU"));
    let Some(rest) = rest else { return raw.to_string() };
    // Wrap it into a mangled variable declaration so the full demangler can
    // deal with templates and nested scopes: `?x@@3V<type>A`.
    let fake = format!("?x@@3V{rest}A");
    if let Ok(s) = msvc_demangler::demangle(&fake, DemangleFlags::llvm()) {
        let s = s.trim();
        let s = s.strip_prefix("class ").or_else(|| s.strip_prefix("struct ")).unwrap_or(s);
        if let Some(t) = s.strip_suffix(" x") {
            return t.trim().to_string();
        }
    }
    let end = rest.find("@@").unwrap_or(rest.len());
    let mut parts: Vec<&str> = rest[..end].split('@').collect();
    parts.reverse();
    parts.join("::")
}

/// `cocos2d::CCNode::getZOrder` -> ("cocos2d::CCNode", "getZOrder").
pub fn split_member(qualified: &str) -> Option<(&str, &str)> {
    // Split at the last `::` that is not inside template brackets.
    let bytes = qualified.as_bytes();
    let mut depth = 0i32;
    let mut split = None;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => depth += 1,
            b'>' => depth -= 1,
            b':' if depth == 0 && bytes.get(i + 1) == Some(&b':') => {
                split = Some(i);
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    split.map(|i| (&qualified[..i], &qualified[i + 2..]))
}

/// Last path component of a class name: `cocos2d::CCNode` -> `CCNode`.
pub fn unqualified(name: &str) -> &str {
    split_member(name).map(|(_, n)| n).unwrap_or(name)
}
