# Activity metadata

Activity Override shows optional English titles alongside internal scenario names. Search matches
either; selecting a row still uses its internal package key. Expand **Known types** beneath
**Activity uses** to see the selected scenario's native activity types. Hover a type for its hash
and direct/playlist provenance. These associations do not select a ruleset or imply playability.

Metadata comes from the user's archived `86657.20.08.23` packages. Titles join metadata definition
tags to scenarios; uses join exact scenario names in investment activities and their playlist
descendants. The existing package worker, reader, BuildData catalog, and cache own this work.
Package I/O does not run on UI frames. No hook, native function address, or live manifest is added.

## Data contract

Read through `state/build_data/runtime.h` using `find_scenario_layout` or
`snapshot_scenario_layouts`. Both return owned copies, independent of the UI and extraction buffers:

```cpp
namespace data = sunrise::state::build_data;
data::scenarios::Definition row{};
if (data::find_scenario_layout(packageName, row)) {
    const std::string_view title(row.activityLabel.data(), row.activityLabelLength);
    const auto uses = std::span(row.activityUses).first(row.activityUseCount);
    // Views belong to this local row. Compare use.typeHash, not its display label.
}
```

- Titles and type labels are optional, length-delimited printable ASCII, at most 48 bytes. A full
  buffer need not have a terminator. Empty titles fall back to the internal name.
- Each scenario holds up to 32 uses, unique and sorted by stable type hash. `sources` combines
  `kDirectActivityUse` and `kPlaylistActivityUse`. Different hashes can have identical labels.
- An empty use set means unclassified. These native types are not the public API mode enum and
  do not retain individual activity IDs, difficulties, modifiers, or playlist paths.
- A whole-catalog snapshot needs caller-owned storage for `scenarios::kDefinitionCapacity`, kept
  off a small stack. Undersized snapshots fail; missing rows differ from rows with empty metadata.

## Validation and fallback

Activity tables validate classes, extents, ordinals, identities, and signed relative pointers.
Playlist traversal is bounded and cycle-safe. Type names require a unique UI root and matching
native/UI identities; unreadable names retain their native hashes. Invalid tables/graphs abandon
type publication, and a use-set overflow leaves that scenario wholly unclassified.

Conflicting title mappings/text and punctuation-only placeholders are suppressed. The string
decoder rejects unsupported encodings and overlong output. `activity_labels` and `activity_types`
logs distinguish read/parse failures, conflicts, name failures, and capacity overflow. Recovered
offsets, classes, and strides are documented beside the parsers in
`middleware/content/packages/tables/activity_metadata_reader.*` and `localized_string_reader.*`.

Cache version 46 stores the metadata and older versions rebuild normally. Canonical validation
checks lengths, text, source flags, ordering, and zeroed unused storage on extraction/restoration.
Changes to stored layout or extraction semantics require cache invalidation. English is the only
verified language; another language needs a measured slot/encoding, decoder/font support, and
language-aware cache handling.

## Tests

The focused synthetic harness covers parsers, graph traversal, and metadata/cache invariants:

```powershell
cmake -S tests/activity_metadata -B build/activity-metadata-tests -G "Visual Studio 18 2026" -A x64
cmake --build build/activity-metadata-tests --config Release
ctest --test-dir build/activity-metadata-tests -C Release --output-on-failure
```

Fixtures contain no game data; parser/graph checks also build with a host C++20 compiler outside
Windows. Catalog/cache checks run on Windows. Runtime validation still needs the exact archived
client: sign-on/orbit, title/internal-name search, repeated selection, unnamed/unclassified
fallbacks, distinct hashes with equal labels, destination loading, clean shutdown, and cold/warm/
stale-cache behavior. Record results in the PR; keep game bytes and captures local.
