# UMH Native Bridge Scaffold

Spark embeds UserModeHook (UMH) capabilities directly into the Windows agent.
This directory now contains both the vendored UMH sources and Spark's bridge
code that exposes them to Go via cgo.

## Layout

- `include/` – Spark-owned headers. `spark_umh.h` defines the narrow C ABI the
  Go layer calls.
- `vendor/include`, `vendor/src`, `vendor/third_party/minhook` – Files copied
  from https://github.com/hira-edu/UserModeHook (MIT). They retain upstream
  license headers and are kept in sync as we upgrade UMH.
- `src/bridge.cc` – Shared C++ bridge (included by the Go cgo package) that
  currently disables `SetWindowDisplayAffinity` and clears `BlockInput`, and will
  evolve into the real UMH runtime glue as we start compiling the vendored
  sources in-tree.
  `SetWindowDisplayAffinity` and clears `BlockInput` using plain User32 calls.
  Replace this with the real UMH entry points as soon as we finish wiring the
  vendored sources.
- `MINIMAL_SOURCESET.md` – Snapshot of the exact UMH translation units we need
  for the first enforcement milestone (SetWindowDisplayAffinity + BlockInput),
  plus the build flags required to keep them service-safe.

## Syncing UMH

1. Clone the upstream repo.
2. Copy `include/`, `src/`, and `third_party/minhook/` into `vendor/` (see the
   current layout for reference) and refresh `vendor/LICENSE.UserModeHook`.
3. Keep the single-executable constraint in mind—no external DLLs or unpacked
   payloads.
4. Extend `spark_umh.h` instead of exposing upstream headers directly to Go;
   the Go bridge should only depend on this file.

## Building

The Go bridge compiles these sources via cgo when the `windows` build tag is
active. The final integration will: (a) compile the real UMH C++ files instead
of the current stub in `src/bridge.cc`, and (b) add the necessary
CXXFLAGS/LDFLAGS so MSVC can produce a statically linked object inside the
Spark executable.
