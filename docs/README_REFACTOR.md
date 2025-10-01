# Agent Code Quality Roadmap

## Why this roadmap exists
The agent codebase has grown organically, leaving a mix of oversized service files, duplicated logic, brittle shell integrations, and loosely typed interfaces. This README breaks the major cleanup opportunities into practical, sequence-friendly workstreams so we can improve reliability without losing momentum.

## Step overview
| Step | Goal | Key wins | Depends on |
| --- | --- | --- | --- |
| 1. Split the service container | Break the 700+ line `ServiceContainer` into targeted bootstrap modules. | Clear dependency wiring, easier testing, faster onboarding. | None |
| 2. Replace `interface{}` plumbing (focus) | Introduce typed WebSocket/command interfaces instead of ad-hoc `interface{}` shims. | Compile-time safety, fewer runtime panics, discoverable APIs. | Step 1 establishes ownership boundaries. |
| 3. Harden concurrency & lifecycle | Guard shared maps, respect contexts, and stop runaway goroutines. | Prevent data races, graceful shutdowns, predictable behavior. | Steps 1–2 reduce coupling before touching concurrency. |
| 4. Modernize shell & package management | Centralize OS detection and stream command output safely. | Lower RAM usage, consistent CLI behavior across distros. | Step 2 ensures typed command service contracts. |
| 5. Streamline logging & monitoring | Add bounded log readers and accurate metrics collection. | Lower memory footprints, more trustworthy telemetry. | Steps 1–4 supply stable foundations. |

---

## Step 1: Split the service container
- **Objective**: Convert the current "god object" in `internal/services/container.go` into lightweight bootstrap units (e.g., `bootstrap/services`, `bootstrap/websocket`, `bootstrap/enrollment`).
- **Tackleable tasks**
  - Create a `bootstrap` package to house construction of logger, config, and core clients.
  - Move mTLS websocket setup + adapter into `internal/websocket/bootstrap` with a narrow interface.
  - Extract enrollment wiring so it only receives typed dependencies (no direct config poking).
  - Introduce per-service registration functions (e.g., `registerDocker`, `registerMonitoring`) returning explicit structs.
  - Add unit smoke tests for the wiring (mocking logger + config) to prevent regression.
- **Done when**: `ServiceContainer` shrinks to orchestration of typed builders with <250 lines and no direct `interface{}` plumbing.

## Step 2: Replace `interface{}` plumbing (primary focus)
- **Objective**: Remove opaque `interface{}` members across services, starting with websocket emitters and managers.
- **Tackleable tasks**
  - Define a `pkg/contracts/websocket` package exporting minimal `Emitter`, `Caller`, `HandlerRegistrar` interfaces.
  - Update `internal/services/interfaces.go` to import these contracts and eliminate `interface{}` placeholders.
  - Refine services (`StatusService`, `MonitoringService`, `BuildService`, etc.) to depend on explicit interfaces and drop runtime type assertions.
  - Add compile-time assertions (`var _ contracts.Emitter = (*websocketAdapter)(nil)`) to protect future changes.
  - Remove duplicated adapter code once the typed contracts are in place (e.g., consolidate `Send/Emit/Call` handling).
- **Done when**: No service struct fields are declared as bare `interface{}`; all websocket usage compiles against shared interfaces.

## Step 3: Harden concurrency & lifecycle
- **Objective**: Make long-running services context-aware and race-safe.
- **Tackleable tasks**
  - Guard shared maps (`buildPlans`, `automationJobs`, `queuedUpdates`) with `sync.RWMutex` or channel-based ownership.
  - Propagate `context.Context` from container start/stop to goroutines; ensure each loop exits when cancelled.
  - Replace polling loops (e.g., websocket wait) with channel notifications or exponential backoff timers.
  - Add integration tests with `go test -race` for key services (deployment, monitoring) once interfaces stabilize.
- **Done when**: Race detector runs on the services package are clean and all long-lived goroutines respect cancellation.

## Step 4: Modernize shell & package management ✅ COMPLETE
- **Objective**: Provide a single command execution utility that handles environment detection, streaming, and error propagation.
- **Tackleable tasks**
  - ✅ Introduce `pkg/runtime/executil` with helpers for streaming stdout/stderr to bounded buffers or channels.
  - ✅ Detect distro/package manager once at startup; store capabilities in config or service container.
  - ✅ Refactor `PackageService` and `CommandService` to compose exec helpers instead of concatenating shell tokens.
  - ✅ Ensure command logs redact sensitive args before logging.
- **Done when**: Shell-based services no longer call `exec.CommandContext` directly, and large outputs no longer cause high memory spikes.
- **Completed**: Created `pkg/runtime` package with `Executor` for bounded command execution, `OSInfo` for cross-platform package manager detection, and refactored `PackageService` and `CommandService` to use the new utilities. Documentation available in `docs/RUNTIME_PACKAGE.md`.

## Step 5: Streamline logging & monitoring
- **Objective**: Deliver accurate metrics and safe log retrieval for large deployments.
- **Tackleable tasks**
  - Replace full-buffer log reads with bounded tail readers (e.g., `bufio.Scanner` with custom split) for Docker and file logs.
  - Cache expensive host metrics (public IP, CPU usage) and expose refresh intervals.
  - Implement Docker stats integration or clearly mark metrics as unavailable to avoid misleading zeros.
  - Wire monitoring alerts to use the typed websocket contracts introduced in Step 2.
- **Done when**: Monitoring services report real values or explicit “unavailable” statuses, and log retrieval scales to large files without high memory use.

---

## Working style tips
- Keep pull requests scoped to a single step/substep to avoid blocking deployments.
- Add regression tests as interfaces evolve; use the typed contracts to generate mock implementations quickly.
- Document any new packages in `docs/` so future contributors understand their role.

Next up: agree on a starting step. The interfaces cleanup (Step 2) is high-impact and now has a dedicated section to guide execution.
