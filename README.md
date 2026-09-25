# gddumper

Offset dumper for the Windows (Steam, x64) build of Geometry Dash, written in Rust.
It reads `GeometryDash.exe`, `libcocos2d.dll` and `libExtensions.dll` directly
(no injection, the game doesn't need to be running) and writes plain-text offset files.

```
cargo build --release
target\release\gddumper.exe            # auto-detects the Steam install, writes .\dump\
```

A full run takes about 3 seconds.

## What it extracts

Everything below comes from the binary itself, so it works on any build of the game,
including updates nobody has reverse engineered yet:

| What | How |
|---|---|
| Classes, inheritance tree, base-class offsets | MSVC RTTI (type descriptors, complete object locators, hierarchy descriptors) |
| Every vtable (primary + secondary subobjects) with all slots | RTTI + vtable scan |
| `sizeof` of classes | sized `operator delete` in deleting destructors, and `operator new(size)` followed by a vtable store or constructor call |
| Constructors, destructors, deleting destructors | vtable stores into `this` / fresh allocations |
| Singletons (`GameManager`, `GameStatsManager`, `CCDirector`, ...) with the global that holds the pointer | lazy-init pattern: allocation stored to a global |
| Member field offsets per class, with access counts and type hints (`i8/i32/f32/f64/ptr/...`) | data-flow tracking of `this` through every method, virtual, ctor and inlined `create()` |
| Cocos2d member names (`CCNode::getPosition` -> 0x4C, ...) | trivial getters/setters among libcocos2d's 5,800 exports |
| Vtable slot names | cocos exports and imports, propagated through the class hierarchy |
| All functions (`.pdata` + discovered leaf functions), globals, string cross-references, imports/exports | PE parsing + disassembly |

### Names

Function and field names aren't stored in the binary. The dumper names what it can work
out on its own:
- cocos2d functions and members from libcocos2d's exports
- constructors, destructors and `operator new/delete`
- singleton globals (`GameManager::s_instance`, ...)
- vtable slots inherited from cocos classes

Everything else starts anonymous (`sub_17B4A0`, field `0x208`). You can name it yourself
with a names file:

```
func   GameManager::sharedState    0x17B4A0
field  GameManager::m_playLayer    0x208
global GameManager::s_instance     0x6C2ED8
```

```
gddumper -n names.txt
```

## Game updates

Every run writes `signatures.txt` for every named function, field and global, and
archives it in `dump/history/<exe timestamp>/`. The next run automatically applies the
most recent history file. It holds byte patterns, vtable-slot references and
field-relative records, so names from the last dumped build are re-found in the new one.

So after a GD update, just run the tool again. Everything automatic (classes, vtables,
sizes, singletons, field offsets) doesn't need names at all. Run it at least once on each
game version so a history exists to carry forward.

## Output (`dump/`)

| File | Contents |
|---|---|
| `offsets.txt` | Singletons/globals, then every class: bases with offsets, `sizeof`, typeinfo, vtables, ctor/dtor, field table (offset, size, type hint, reads/writes, name) |
| `vtables.txt` | Every vtable slot: index, byte offset, target RVA, name, inherited/import/thunk notes |
| `functions.txt` | Every function: RVA, size, name, name source, `this` class, trivial-body summary |
| `globals.txt` | Globals in writable sections with read/write counts |
| `strings.txt` | String literals and the functions that reference them |
| `imports_exports.txt` | IAT slots and exports (demangled) |
| `signatures.txt` | Signatures for the next update (also usable by hand) |
| `dump.json` | Machine-readable version of classes, vtables, fields and names |

All addresses are **RVAs**: absolute address = module base + RVA.

Example (`offsets.txt`):

```
GameManager                        GeometryDash.exe+0x6C2ED8   accessor sub_17B4A0 (0x17B4A0)  sizeof 0x668

class PlayLayer : GJBaseGameLayer @0x0, CCCircleWaveDelegate @0x37A0, CurrencyRewardDelegate @0x37A8, DialogDelegate @0x37B0
    module GeometryDash.exe   sizeof 0x3A88 (sized delete)
    ...
      0x39EF     1 i8         r1 w3 a0              4
```

## Options

```
gddumper [dump] [-g <game dir>] [-o <out dir>] [-s signatures.txt]... [-n names.txt]...
                [--no-history] [--no-sigs] [--modules a.exe,b.dll]
gddumper scan <signatures.txt> [--exe GeometryDash.exe]   # resolve a signature file and print results
gddumper disasm <module> <rva> [count]                    # quick disassembly listing
```

`-n names.txt` adds your own names (one per line, `func|field|global Class::name 0xOFFSET`).
They get signatures like everything else, so they survive updates too.

### Signature format

```
[GeometryDash.exe]
func   PlayLayer::resetLevel      48 89 5C 24 ?? 57 48 83 EC 20 ...     ; match address
func   Foo::bar                   E8 [rel32] 48 8B D8                   ; call target
field  PlayLayer::m_isPaused      80 BB [i32] 00 74 ?? +0x0             ; captured displacement (+ adjust)
global GameManager::s_instance    48 8B 05 [rel32] 48 85 C0
vslot  PlayLayer::checkSnapshot   PlayLayer +0x0 170                    ; vtable slot
rel    PlayLayer::m_unk36cd       PlayLayer::m_unk36cc +0x1             ; relative to another field
```

## Limitations

- Windows x64 builds only (PE/MSVC). Android and macOS builds aren't supported.
- Field *offsets* are found automatically, but field *names* aren't stored in the binary.
  They come from your names file and the signature history. A field the game code never
  touches through a recognisable `this` pointer doesn't show up.
- Type hints come from access widths (`ptr`, `f32`, ...), not real C++ types.
- The two fallback kinds are heuristic. A `vslot` record breaks if a new virtual is
  inserted before it. A `rel` record breaks if a field is inserted between it and its anchor.
