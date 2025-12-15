# Repository Guidelines

## Project Structure & Module Organization

- `server/`: Go server (`server/main.go`) exposing the HTTP API and realtime channels; embeds the web UI.
- `client/`: Go client/agent (services, desktop capture/input, IPC, transport).
- `web/`: React + Ant Design frontend (webpack). Production output: `web/dist/`.
- `server/embed/web/statik.go`: generated embedded assets (do not edit by hand).
- `docs/`: deeper references (build, configuration, deployment, architecture).
- `scripts/`: build helpers for server/client/web across platforms.
- `utils/`, `modules/`, `observability/`: shared helpers, module registration, and telemetry tooling.

## Build, Test, and Development Commands

- Go toolchain is pinned in `go.mod` (`toolchain ...`); use a compatible Go version.
- Run server locally: `go run ./server` (expects `./config.json`; start from `config.example.json`).
- Build server: `go build -o rocket-server ./server`
- Web dev server: `cd web; npm install; npm run start`
- Note: `web/package.json` scripts use Windows-style env setting; on macOS/Linux set `NODE_ENV` in your shell (see `docs/BUILD.md`).
- Web production build + embed (required for server UI):
  - `cd web; npm install; npm run build-prod`
  - `statik -src=./web/dist -dest=./server/embed -p web -ns web -f` (namespace **must** be `web`)
- Cross-build scripts:
  - `./scripts/build.server.sh` (outputs to `releases/`)
  - `./scripts/build.client.sh` (outputs to `built/`)

## Coding Style & Naming Conventions

- Go: run `gofmt` on all changes; keep package names lower-case and file names descriptive (`snake_case.go`).
- Web: follow the existing JS/JSX style (tabs and simple imports); keep UI code under `web/src/`.
- Generated artifacts: only regenerate `server/embed/web/statik.go` when `web/` output changes.

## Testing Guidelines

- Go: `go test ./...` (unit tests live next to packages as `*_test.go`).
- Web E2E (when touching desktop/websocket flows): `cd web; npx playwright test` (run `npx playwright install` once; see `web/e2e/*.spec.js`).

## Commit & Pull Request Guidelines

- Commits typically use a scoped subject like `Desktop: ...`, `Server: ...`, `Windows: ...`; keep it imperative and focused.
- PRs should include: what/why, how to test, any config changes, and screenshots for `web/` UI updates.

## Security & Configuration Tips

- Never commit secrets: `config.json`, `logs/`, `built/`, and most `releases/` outputs are intentionally ignored.
- Report security issues privately; follow the instructions in `README.md`.
