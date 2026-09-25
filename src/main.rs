mod analysis;
mod bindings;
mod dump;
mod model;
mod names;
mod output;
mod pe;
mod rtti;
mod sigs;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Geometry Dash offset dumper: RTTI classes, vtables, class sizes,
/// constructors, singletons, field offsets, functions, globals and strings.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    #[command(flatten)]
    dump: DumpArgs,
}

#[derive(Subcommand)]
enum Cmd {
    /// Dump everything to text files (default command).
    Dump(DumpArgs),
    /// Resolve a signature file against a binary and print the results.
    Scan {
        /// GeometryDash.exe to scan.
        #[arg(long)]
        exe: Option<PathBuf>,
        sigs: PathBuf,
    },
    /// Print a disassembly listing at an RVA.
    Disasm {
        module: PathBuf,
        rva: String,
        #[arg(default_value_t = 40)]
        count: usize,
    },
    /// List Geode bindings versions available on GitHub.
    Versions,
}

#[derive(Args, Clone)]
struct DumpArgs {
    /// Geometry Dash install folder (auto-detected from Steam when omitted).
    #[arg(long, short = 'g')]
    game_dir: Option<PathBuf>,
    /// Output folder.
    #[arg(long, short = 'o', default_value = "dump")]
    out: PathBuf,
    /// Modules to analyse, comma separated.
    #[arg(long, default_value = "GeometryDash.exe,libcocos2d.dll,libExtensions.dll", value_delimiter = ',')]
    modules: Vec<String>,
    /// Geode bindings: a folder with GeometryDash.bro/Extras.bro/Enums.hpp, or a single .bro file.
    #[arg(long, short = 'b')]
    bindings: Option<PathBuf>,
    /// Geode bindings version to download from GitHub (e.g. 2.2081), or `auto`
    /// to pick the version whose addresses match this binary.
    #[arg(long, default_value = "auto")]
    bindings_version: String,
    /// Never touch the network (only cached bindings / local files are used).
    #[arg(long)]
    offline: bool,
    /// Do not load or save signature history (<out>/history).
    #[arg(long)]
    no_history: bool,
    /// Apply bindings even when their addresses do not match this binary.
    #[arg(long)]
    force_bindings: bool,
    /// Signature files (e.g. signatures.txt from a previous dump). Repeatable.
    #[arg(long, short = 's')]
    sigs: Vec<PathBuf>,
    /// Explicit names: lines of `func|field|global Class::name 0xOFFSET`. Repeatable.
    #[arg(long, short = 'n')]
    names: Vec<PathBuf>,
    /// Do not generate signatures.txt.
    #[arg(long)]
    no_sigs: bool,
    /// Also generate signatures for fields of classes whose layout was not verified.
    #[arg(long)]
    sig_unverified_fields: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        None => run_dump(cli.dump),
        Some(Cmd::Dump(a)) => run_dump(a),
        Some(Cmd::Scan { exe, sigs: file }) => {
            let exe = match exe {
                Some(e) => e,
                None => dump::default_game_dir().context("could not find Geometry Dash; pass --exe")?.join("GeometryDash.exe"),
            };
            let m = model::Module::load(&exe)?;
            let list: Vec<sigs::Sig> =
                sigs::parse(&std::fs::read_to_string(&file)?)?.into_iter().filter(|s| s.module.eq_ignore_ascii_case(&m.pe.name)).collect();
            let res = sigs::apply(&m, &list);
            let mut ok = 0;
            for r in &res {
                match r.value {
                    Some(v) => {
                        ok += 1;
                        println!("{:<6} {:<50} {:#x}", r.sig.kind.label(), r.sig.name, v);
                    }
                    None => println!("{:<6} {:<50} FAILED ({} matches)", r.sig.kind.label(), r.sig.name, r.matches),
                }
            }
            eprintln!("{ok}/{} resolved", res.len());
            Ok(())
        }
        Some(Cmd::Disasm { module, rva, count }) => {
            let pe = pe::Pe::load(&module)?;
            let rva = u32::from_str_radix(rva.trim_start_matches("0x").trim_start_matches("0X"), 16)?;
            disasm(&pe, rva, count);
            Ok(())
        }
        Some(Cmd::Versions) => {
            for v in bindings::remote_versions()? {
                println!("{v}");
            }
            Ok(())
        }
    }
}

fn run_dump(a: DumpArgs) -> Result<()> {
    let t = std::time::Instant::now();
    let game_dir = match a.game_dir.clone() {
        Some(d) => d,
        None => dump::default_game_dir().context("could not find Geometry Dash; pass --game-dir")?,
    };
    if !game_dir.join("GeometryDash.exe").exists() {
        bail!("{} does not contain GeometryDash.exe", game_dir.display());
    }
    eprintln!("[+] game folder: {}", game_dir.display());

    let exe_path = game_dir.join("GeometryDash.exe");
    let exe_ts = pe::Pe::load(&exe_path)?.timestamp;

    let mut bindings = a.bindings.clone();
    if bindings.is_none() {
        let cache = a.out.join("bindings");
        let picked = if a.bindings_version != "auto" {
            if a.offline { Some(cache.join(&a.bindings_version)).filter(|p| p.exists()) } else { Some(bindings::fetch_version(&a.bindings_version, &cache)?) }
        } else {
            match pick_bindings(&exe_path, &cache, !a.offline) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[!] could not get Geode bindings ({e:#}); continuing without them");
                    None
                }
            }
        };
        bindings = picked;
    }

    // Signatures saved by earlier runs keep names alive across game updates.
    let mut sig_files = a.sigs.clone();
    let history = a.out.join("history");
    if !a.no_history && a.sigs.is_empty() {
        if let Some(prev) = latest_history(&history, exe_ts) {
            eprintln!("[+] using signature history {}", prev.display());
            sig_files.push(prev);
        }
    }

    let opts = dump::Options {
        game_dir,
        modules: a.modules.clone(),
        bindings,
        force_bindings: a.force_bindings,
        sigs: sig_files,
        names: a.names.clone(),
    };
    let report = dump::run(&opts)?;
    let (sig_list, extras, failed) = if a.no_sigs {
        (vec![], vec![], vec![])
    } else {
        let t2 = std::time::Instant::now();
        let r = dump::make_signatures(&report, a.sig_unverified_fields);
        eprintln!(
            "[+] signatures: {} patterns, {} fallback records, {} without any ({:.2?})",
            r.0.len(),
            r.1.len(),
            r.2.len(),
            t2.elapsed()
        );
        r
    };
    output::write_all(&report, &a.out, &sig_list, &extras, &failed)?;
    if !a.no_history && !sig_list.is_empty() {
        let dir = history.join(format!("{exe_ts:08x}"));
        std::fs::create_dir_all(&dir)?;
        std::fs::copy(a.out.join("signatures.txt"), dir.join("signatures.txt"))?;
    }

    let w = &report.world;
    let fields: usize = w.fields.values().map(|f| f.len()).sum();
    let named_fields: usize = report.named_fields.values().flat_map(|f| f.values()).map(|v| v.len()).sum();
    let verified = report.layout_status.values().filter(|s| matches!(s, dump::LayoutStatus::Verified { .. })).count();
    let named_funcs: usize = w.modules.iter().map(|m| m.names.len()).sum();
    eprintln!(
        "[+] {} classes, {} observed fields, {} named fields ({} layouts verified), {} named functions",
        w.classes.len(),
        fields,
        named_fields,
        verified,
        named_funcs
    );
    eprintln!("[+] wrote {} in {:.2?}", a.out.display(), t.elapsed());
    Ok(())
}

/// Signatures from the current game build if it was dumped before, else from
/// the most recently dumped other build.
fn latest_history(history: &Path, exe_ts: u32) -> Option<PathBuf> {
    let same = history.join(format!("{exe_ts:08x}")).join("signatures.txt");
    if same.exists() {
        return Some(same);
    }
    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(history)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path().join("signatures.txt"))
        .filter(|p| p.exists())
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .collect();
    entries.sort();
    entries.pop().map(|e| e.1)
}

/// Try bindings versions newest-first and keep the one whose Windows
/// addresses best match this binary's function table.
fn pick_bindings(exe: &Path, cache: &Path, online: bool) -> Result<Option<PathBuf>> {
    let pe = pe::Pe::load(exe)?;
    let starts: HashSet<u32> = pe.runtime_functions.iter().map(|f| f.begin).collect();
    let mut best: Option<(f64, PathBuf, String)> = None;
    let versions = if online {
        bindings::remote_versions()?
    } else {
        let mut v: Vec<String> = std::fs::read_dir(cache)
            .map(|d| d.filter_map(|e| e.ok()).filter(|e| e.path().join("GeometryDash.bro").exists()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        v.sort_by(|a, b| b.parse::<f64>().unwrap_or(0.0).partial_cmp(&a.parse::<f64>().unwrap_or(0.0)).unwrap());
        v
    };
    for v in versions {
        eprintln!("[.] trying bindings {v}");
        let dir = if online {
            match bindings::fetch_version(&v, cache) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("    {e}");
                    continue;
                }
            }
        } else {
            cache.join(&v)
        };
        let mut b = bindings::Bindings::default();
        b.parse_bro(&std::fs::read_to_string(dir.join("GeometryDash.bro"))?);
        let addrs: Vec<u32> = b.functions().filter_map(|f| f.win).collect();
        if addrs.is_empty() {
            continue;
        }
        let ratio = addrs.iter().filter(|a| starts.contains(a)).count() as f64 / addrs.len() as f64;
        eprintln!("    {:.1}% of {} addresses match", ratio * 100.0, addrs.len());
        if best.as_ref().is_none_or(|b| ratio > b.0) {
            best = Some((ratio, dir, v.clone()));
        }
        if ratio > 0.9 {
            break;
        }
    }
    let Some((ratio, dir, v)) = best else { return Ok(None) };
    if ratio < 0.85 {
        eprintln!(
            "[!] no published bindings match this binary (best: {v} at {:.1}%) - probably a new game update.\n    \
             Function names come from signature history; {v}'s member layouts are still checked per class against measured sizes.",
            ratio * 100.0
        );
    } else {
        eprintln!("[+] using bindings {v} ({:.1}% match)", ratio * 100.0);
    }
    Ok(Some(dir))
}

pub fn disasm(pe: &pe::Pe, rva: u32, n: usize) {
    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
    let bytes = pe.bytes(rva, n * 15);
    let mut d = Decoder::with_ip(64, bytes, pe.rva_to_va(rva), DecoderOptions::NONE);
    let mut f = IntelFormatter::new();
    let mut s = String::new();
    for _ in 0..n {
        if !d.can_decode() {
            break;
        }
        let i = d.decode();
        s.clear();
        f.format(&i, &mut s);
        let raw: Vec<String> = pe.bytes((i.ip() - pe.image_base) as u32, i.len()).iter().map(|b| format!("{b:02X}")).collect();
        println!("  {:#010x}  {:<30} {}", i.ip() - pe.image_base, raw.join(" "), s);
    }
}
