# Spark Agent – Registry Footprint Manifest (Windows)

Current Windows builds of the Spark agent are intentionally “registry-light.” The executable stores its configuration in files under `%ProgramData%\Spark` and does not persist operational state in the registry. This manifest documents the *only* keys Spark may touch today so customers can validate compliance and plan cleanup procedures.

| Key Path | Value(s) | Purpose | Created? | Removal Notes |
|----------|----------|---------|----------|---------------|
| (none) | — | — | ❌ | The agent does not create or modify any registry keys in this release. |

## Reserved Namespace

To support future policy/telemetry features, we reserve `HKLM\Software\Spark` for storing:

1. `InstallPath` – canonical install directory (`C:\ProgramData\Spark`).
2. `Version` – semantic version of the installed agent.
3. `ConfigChecksum` – hash of `config.json` for drift detection.

These values are **not** written yet. When we introduce them we will update this manifest and the installer/uninstaller scripts to:

- Create keys under `HKLM\Software\Spark` with `SYSTEM` + service SID access only.
- Remove the entire branch during uninstall (unless `SPARK_PRESERVE_REGISTRY=1` is set for forensic retention).

## Audit & Cleanup Guidance

- Compliance teams can confirm the current footprint by inspecting `HKLM\Software` – Spark should not appear unless you pre-create the reserved namespace.
- Uninstall procedures only need to delete the executable and `%ProgramData%\Spark`; there are no registry artefacts to scrub in today’s builds.
- If group policies forbid new registry keys, Spark still operates because it relies entirely on file-based configuration.

This document should be revisited once UMH integration or watchdog telemetry requires persistent registry state.
