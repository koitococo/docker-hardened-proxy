# Configurable Denied Response Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a configuration-controlled denied response mode so operators can choose between the legacy detailed deny body and a generic deny body without changing the underlying audit decisions.

**Architecture:** Extend `internal/config` with an enum-like `audit.denied_response_mode` setting that defaults to the current main-branch behavior. Centralize 403 deny body rendering in `internal/proxy/proxy.go` so all audited and namespace denial paths use one helper. Keep audit modules returning detailed reasons internally, and update tests to verify both config parsing and response rendering behavior.

**Tech Stack:** Go 1.25, YAML config parsing via `gopkg.in/yaml.v3`, Go standard library `net/http`, existing Python integration harness under `tests/`.

---

### Task 1: Add config model and validation for denied response mode

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Step 1: Write the failing config tests**

Add table-driven coverage in `internal/config/config_test.go` for:
- default mode resolves to `reason`
- explicit `audit.denied_response_mode: reason` parses successfully
- explicit `audit.denied_response_mode: generic` parses successfully
- invalid value like `audit.denied_response_mode: noisy` returns a validation error

Use assertions in the style already present in `config_test.go`.

**Step 2: Run config tests to verify failure**

Run: `go test ./internal/config -run DeniedResponseMode -v`

Expected: FAIL because the config field/validation does not exist yet.

**Step 3: Write minimal implementation**

In `internal/config/config.go`:
- add string field on `AuditConfig`:

```go
DeniedResponseMode string `yaml:"denied_response_mode"`
```

- define constants near config types, e.g.:

```go
const (
	DeniedResponseModeReason  = "reason"
	DeniedResponseModeGeneric = "generic"
)
```

- set default in `defaultConfig()` to `DeniedResponseModeReason`
- validate allowed values in `(*Config).validate()` and return a wrapped error for unsupported values

Keep the implementation small and enum-like; do not add boolean aliases.

**Step 4: Run config tests to verify pass**

Run: `go test ./internal/config -v`

Expected: PASS.

**Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add denied response mode config"
```

### Task 2: Centralize denied response rendering in proxy

**Files:**
- Modify: `internal/proxy/proxy.go`
- Modify: `internal/proxy/proxy_test.go`

**Step 1: Write the failing handler tests**

Add focused tests in `internal/proxy/proxy_test.go` that verify denied body content for at least these representative paths:
- container create deny returns detailed reason in default mode
- container create deny returns generic message in generic mode
- unknown endpoint deny returns detailed reason in default mode
- buildkit top-level deny returns generic message when configured

Prefer exact body assertions like:

```go
if got := w.Body.String(); got != "denied: privileged mode is denied\n" {
	t.Fatalf("body = %q", got)
}
```

and

```go
if got := w.Body.String(); got != "denied by policy\n" {
	t.Fatalf("body = %q", got)
}
```

**Step 2: Run proxy tests to verify failure**

Run: `go test ./internal/proxy -run DeniedResponse -v`

Expected: FAIL because response rendering is still duplicated and not mode-aware.

**Step 3: Write minimal implementation**

In `internal/proxy/proxy.go`:
- add a helper on `Handler`, for example:

```go
func (h *Handler) writeDeniedResponse(w http.ResponseWriter, reason string)
```

- implement mode selection using `h.cfg.Audit.DeniedResponseMode`
- `reason` mode should render `"denied: " + reason`
- `generic` mode should render `"denied by policy"`
- replace direct `http.Error(..., "denied: ...")` deny paths in `ServeHTTP`, `handleExecCreate`, `handleImagePull`, `handleBuild`, `handleBuildKit`, `handleBuildKitSession`, `handleBuildKitControl`, `handleAuth`, `handleImagePush`, and `handleContainerCreate` with the helper
- keep non-deny errors unchanged (`400`, `405`, `500`, oversized body, etc.)

Do not change audit reason generation; only change response formatting.

**Step 4: Run proxy tests to verify pass**

Run: `go test ./internal/proxy -v`

Expected: PASS.

**Step 5: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/proxy_test.go
git commit -m "feat: make deny responses configurable"
```

### Task 3: Document and expose the new config in sample config

**Files:**
- Modify: `config.example.yaml`
- Modify: `README.md`

**Step 1: Write the documentation update**

Update `config.example.yaml` to include:

```yaml
audit:
  denied_response_mode: "reason"
```

Add comments describing:
- `reason` keeps legacy detailed deny messages
- `generic` returns `denied by policy`

Update `README.md` with a short section documenting the option and its security/compatibility trade-off.

**Step 2: Review for clarity**

Confirm docs explain why an operator might choose each mode and that default is compatibility-first.

**Step 3: Commit**

```bash
git add config.example.yaml README.md
git commit -m "docs: document denied response modes"
```

### Task 4: Add integration coverage for generic mode without destabilizing existing tests

**Files:**
- Modify: `tests/README.md`
- Create: `tests/generic-denied-response-unknown-endpoint/config.yaml`
- Create: `tests/generic-denied-response-unknown-endpoint/run_test.py`

**Step 1: Write a new integration test for generic mode**

Create one focused integration case instead of rewriting all existing legacy tests. The new test should:
- start proxy with `audit.denied_response_mode: generic`
- call a denied endpoint like `/definitely-not-allowed`
- assert status `403`
- assert body equals or contains `denied by policy`

Follow the existing test directory structure and harness conventions.

**Step 2: Run the new integration test to verify failure**

Run: `DOCKER_HOST=unix:///home/ubuntu/.run/docker.sock uv run python3 generic-denied-response-unknown-endpoint/run_test.py`

Expected: FAIL until the config and proxy helper are implemented.

**Step 3: Update tests README if needed**

Add a brief note that response contract tests may depend on `audit.denied_response_mode`.

**Step 4: Run the focused integration test to verify pass**

Run: `DOCKER_HOST=unix:///home/ubuntu/.run/docker.sock uv run python3 generic-denied-response-unknown-endpoint/run_test.py`

Expected: PASS.

**Step 5: Commit**

```bash
git add tests/README.md tests/generic-denied-response-unknown-endpoint
git commit -m "test: cover generic deny response mode"
```

### Task 5: Final verification

**Files:**
- Modify: none

**Step 1: Run unit and package tests**

Run: `go test ./...`

Expected: PASS.

**Step 2: Run integration suite**

Run: `DOCKER_HOST=unix:///home/ubuntu/.run/docker.sock uv run run_parallel.py --workers 4`

Expected: PASS, including the new generic-mode test and all legacy response tests still passing.

**Step 3: Summarize verification evidence**

Capture:
- `go test ./...` output
- integration summary line
- any updated report paths under `tests/reports/`

**Step 4: Commit final verification-only changes if needed**

Only commit tracked source/docs/tests changed above; do not commit generated reports.
