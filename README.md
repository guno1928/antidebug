# antidebug

A production-grade anti-debug and anti-tamper library for Go. Detects debuggers, sandboxes, instrumentation hooks, and analysis environments at runtime — on both Windows and Linux — with zero CGO and zero external dependencies.

use with https://github.com/burrowers/garble for best results.

---

## Features

- **Fast checks** (default every 200 ms): `IsDebuggerPresent`, heap flags, NtGlobalFlag, parent process, timing anomalies, hardware breakpoints (DR0–DR7)
- **Slow checks** (default every 5 s): ETW patch detection, AMSI patch detection, `DbgUiRemoteBreakin` patch detection, `ntdll.dll` page-private detection, injected DLL scan, RWX region scan, process integrity level
- **Timing-based detection**: rolling baseline with configurable multiplier; detects single-step, breakpoint stalls, and VM slowdowns
- **Deferred action**: configurable random delay between detection and response — creates a false sense of safety for analysts
- **CGO-free**: builds with `CGO_ENABLED=0` for both Windows and Linux amd64
- **Diagnostics**: structured dump of OS state, CPUID, network interfaces, environment variables, and all debug indicators for comparison between clean and sandboxed runs

---

## Tested Against

Tested on **Windows 10/11 x64** using [x64dbg](https://x64dbg.com/) with the [ScyllaHide](https://github.com/x64dbg/ScyllaHide) anti-anti-debug plugin.

All ScyllaHide profiles were tested — every one was detected and blocked:

| Profile | Result |
|---|---|
| VMProtect | ✅ Detected |
| Themida | ✅ Detected |
| Obsidian | ✅ Detected |
| Armadillo | ✅ Detected |

---

## Requirements

- Go 1.21+
- Windows amd64 or Linux amd64
- `CGO_ENABLED=0` supported

---

## Installation

```bash
go get github.com/guno1928/antidebug/core
```

---

## Quick Start

```go
package main

import (
    "fmt"
    "os"
    "time"

    antidebug "github.com/guno1928/antidebug/core"
)

func main() {
    cfg := antidebug.DefaultConfig()

    cfg.OnDetect = func(reason string) {
        // Called after a random delay — do not trust this timing for cleanup
        fmt.Fprintln(os.Stderr, "tampering detected:", reason)
        os.Exit(1)
    }

    antidebug.Start(cfg)

    // Your application logic here
    for {
        time.Sleep(3 * time.Second)
        if antidebug.IsCompromised() {
            fmt.Println("Compromised flag raised — deferred action pending")
        }
    }
}
```

---

## Custom Configuration

```go
package main

import (
    "fmt"
    "os"
    "time"

    antidebug "github.com/guno1928/antidebug/core"
)

func main() {
    cfg := antidebug.DefaultConfig()

    // Tune check frequency
    cfg.CheckInterval    = 100 * time.Millisecond
    cfg.SlowCheckEvery   = 10

    // Timing sensitivity — higher = more sensitive to slowdowns
    cfg.TimingMultiplier = 4.0
    cfg.TimingMinSamples = 30

    // Deferred response window — analyst sees a working app for 5-10s after detection
    cfg.DeferredMinDelay = 5 * time.Second
    cfg.DeferredMaxDelay = 10 * time.Second

    // Enable file logging
    cfg.DebugMode   = true
    cfg.LogFilePath = "antidebug.log"

    cfg.OnDetect = func(reason string) {
        fmt.Fprintln(os.Stderr, "tampering detected:", reason)
        os.Exit(1)
    }

    antidebug.Start(cfg)

    fmt.Println("Protection active.")
    select {}
}
```

---

## Diagnostics

`antidebug.Diagnostics()` returns a formatted string containing:

- OS, architecture, Go runtime version
- Network interfaces and addresses
- Environment variables
- Platform-specific debug state (all check results)
- CPUID hypervisor and vendor information

Useful for comparing output between a clean machine and a sandboxed or debugged environment.

```go
fmt.Print(antidebug.Diagnostics())
```

---

## Config Reference

| Field | Type | Default | Description |
|---|---|---|---|
| `OnDetect` | `func(string)` | print + exit | Called after deferred delay when tampering is confirmed |
| `CheckInterval` | `time.Duration` | `200ms` | How often the fast check loop runs |
| `SlowCheckEvery` | `int` | `25` | Run slow checks every N fast-check cycles |
| `TimingMultiplier` | `float64` | `3.0` | Timing anomaly threshold multiplier |
| `TimingMinSamples` | `int` | `20` | Baseline samples before timing checks activate |
| `DeferredMinDelay` | `time.Duration` | `3s` | Minimum delay between detection and `OnDetect` call |
| `DeferredMaxDelay` | `time.Duration` | `8s` | Maximum delay between detection and `OnDetect` call |
| `DebugMode` | `bool` | `false` | Enable verbose logging |
| `LogFilePath` | `string` | `""` | Write log to file (empty = stdout only) |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
