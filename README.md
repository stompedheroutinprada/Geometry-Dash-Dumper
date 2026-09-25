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
| All functions (`.pdata` + discovered leaf functions), globals, string cross-references, imports/exports | PE parsing + disassembly (iced-x86) |

### Names (Geode bindings)

By default the tool downloads the Geode bindings from
[geode-sdk/bindings](https://github.com/geode-sdk/bindings) and picks the version whose
addresses match your binary. From those it takes:

- **Function names:** every `win 0x...` address, checked against the function table.
  Virtuals declared `win inline` are placed by declaration order.
- **Member names with offsets:** a built-in MSVC x64 layout engine lays out the declared
  members. The start offset comes from the base-class sizes measured in the binary.
  - Each class's computed size is compared with the measured `sizeof`:
    `VERIFIED` (about 417 classes, including `PlayLayer`, `GJBaseGameLayer`, `PlayerObject` and `GameManager`),
    `MISMATCH` (the bindings are wrong for that class), or `incomplete`.
  - Embedded structs are flattened to full paths, e.g. `GJBaseGameLayer::m_gameState.m_cameraZoom`.
  - Cross-check on 2.2081: 99.9% of named fields that the code accesses are accessed
    with the size their declared type implies.

## Game updates

Every run writes `signatures.txt` and archives it in `dump/history/<exe timestamp>/`.
On the next run:

1. If published bindings match the new build, they are used.
2. Otherwise the most recent history file is applied. It holds byte patterns
   (functions, fields, globals), vtable-slot references and field-relative records, so
   names from the last dumped build are re-found in the new one.
3. The old bindings' member layouts are still computed and size-checked per class.

So after a GD update, just run the tool again. Measured on 2.2081 with bindings switched
off and only the history file: 100% of patterns resolve uniquely to the original addresses.
About 88% of named functions and 88% of named fields come back, with no wrong offsets.
Everything automatic (classes, vtables, sizes, singletons, field offsets) doesn't need
names at all.

Run it at least once on each game version, before or right after updating, so a
history exists to carry forward.

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
GameManager                        GeometryDash.exe+0x6C2ED8   accessor GameManager::sharedState (0x17B4A0)  sizeof 0x668

class PlayLayer : GJBaseGameLayer @0x0, CCCircleWaveDelegate @0x37A0, CurrencyRewardDelegate @0x37A8, DialogDelegate @0x37B0
    module GeometryDash.exe   sizeof 0x3A88 (sized delete)   bindings layout: VERIFIED (ends at 0x3A88)
    ...
      0x39EF     1 i8         r1 w3 a0              4  m_isPaused [B] : bool
```

## Options

```
gddumper [dump] [-g <game dir>] [-o <out dir>] [-b <bindings dir|.bro>] [--bindings-version 2.2081|auto]
                [--offline] [-s signatures.txt]... [-n names.txt]... [--no-history] [--no-sigs]
                [--force-bindings] [--sig-unverified-fields] [--modules a.exe,b.dll]
gddumper scan <signatures.txt> [--exe GeometryDash.exe]   # resolve a signature file and print results
gddumper disasm <module> <rva> [count]                    # quick disassembly listing
gddumper versions                                         # list Geode bindings versions
```

`-n names.txt` adds your own names: one per line, `func|field|global Class::name 0xOFFSET`.
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
relsub GJGameState::m_cameraZoom  GJBaseGameLayer::m_gameState.m_cameraZoom GJBaseGameLayer::m_gameState
```

## Limitations

- Windows x64 builds only (PE/MSVC). Android and macOS builds aren't supported.
- Field *offsets* are found automatically, but field *names* aren't stored in the binary.
  They come from Geode bindings, signature history or your names file. A field the game
  code never touches through a recognisable `this` pointer shows up only if the bindings
  declare it.
- Type hints come from access widths (`ptr`, `f32`, ...), not real C++ types.
- A `MISMATCH` status means the bindings disagree with the binary for that class; its
  names may be shifted.
- The two fallback kinds are heuristic. A `vslot` record breaks if a new virtual is
  inserted before it. A `rel` record breaks if a field is inserted between it and its anchor.
