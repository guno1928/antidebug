// Package antidebug provides continuous background anti-debugging and
// anti-analysis protection for Go programs.
//
// Call [Start] once, as early as possible in main, to begin monitoring. When
// tampering is detected the package does not terminate the process immediately;
// instead it waits a randomized delay (the "false hope" window) so that the
// analyst observes no behavioural change, then calls the configured
// [Config.OnDetect] callback.
//
// Minimal usage:
//
//	antidebug.Start(antidebug.DefaultConfig())
//
// Custom callback:
//
//	cfg := antidebug.DefaultConfig()
//	cfg.OnDetect = func(reason string) {
//		log.Printf("tamper detected: %s", reason)
//		os.Exit(1)
//	}
//	antidebug.Start(cfg)
package antidebug

import (
	"math/rand"
	"sync/atomic"
	"time"
)

// Config controls every aspect of the antidebug package. All fields are
// optional — call [DefaultConfig] to obtain a fully-populated starting point
// and then override only the fields you need before passing the Config to
// [Start].
//
// Example — minimal custom setup:
//
//	cfg := antidebug.DefaultConfig()
//	cfg.OnDetect = func(reason string) {
//		log.Printf("tampering detected: %s", reason)
//		os.Exit(1)
//	}
//	antidebug.Start(cfg)
//
// Example — aggressive tuning for a high-value target:
//
//	cfg := antidebug.DefaultConfig()
//	cfg.CheckInterval    = 50 * time.Millisecond
//	cfg.TimingMultiplier = 5.0
//	cfg.DeferredMinDelay = 1 * time.Minute
//	cfg.DeferredMaxDelay = 5 * time.Minute
//	cfg.DebugMode        = true
//	cfg.LogFilePath      = "/var/log/myapp-antidebug.log"
//	antidebug.Start(cfg)
type Config struct {
	// CheckInterval controls how often the fast background goroutine re-runs
	// lightweight detection checks (timing anomalies, debugger flags, PEB
	// fields, /proc/self/status). Lower values increase responsiveness at the
	// cost of a tiny amount of extra CPU use.
	// Default: 200ms. Minimum effective value: 10ms.
	CheckInterval time.Duration

	// SlowCheckInterval controls how often the slow background goroutine
	// re-runs expensive checks (virtual-memory walks, injected-library scans,
	// working-set queries). Keep this value high on machines with constrained
	// resources — the checks are thorough but not free.
	// Default: 5s.
	SlowCheckInterval time.Duration

	// TimingMultiplier is the factor by which a timed operation must exceed
	// the rolling-minimum baseline before it is considered suspicious. Higher
	// values reduce false positives caused by transient CPU load at the cost
	// of missing slow single-step debuggers.
	// Default: 10.0. Recommended range: 5.0–20.0.
	TimingMultiplier float64

	// DebugMode enables verbose logging of every detection event to the file
	// at LogFilePath. Disable in production builds to avoid leaving artefacts
	// on disk that reveal detection logic.
	// Default: false.
	DebugMode bool

	// LogFilePath is the path to the log file written when DebugMode is true.
	// The file is created if it does not exist and appended to otherwise.
	// Has no effect when DebugMode is false.
	// Default: "antidebug.log".
	LogFilePath string

	// OnDetect is called exactly once, after the deferred delay, when
	// tampering is first detected. The reason parameter is a human-readable
	// description of which check fired and why. Subsequent detections are
	// logged (if DebugMode is on) but do not call OnDetect again.
	// Default: calls os.Exit(1).
	OnDetect func(reason string)

	// DeferredMinDelay is the lower bound of the random delay between the
	// first detection event and the OnDetect call. Increase this to extend
	// the false-hope window and make the detection harder to notice.
	// Default: 30s.
	DeferredMinDelay time.Duration

	// DeferredMaxDelay is the upper bound of the random delay. The actual
	// delay is chosen uniformly at random in [DeferredMinDelay, DeferredMaxDelay].
	// Must be greater than DeferredMinDelay; if not, it is automatically
	// adjusted to DeferredMinDelay + 2 minutes.
	// Default: 1 minute.
	DeferredMaxDelay time.Duration
}

// DefaultConfig returns a [Config] populated with production-ready defaults.
// It is the recommended starting point for any Config passed to [Start].
// All returned values may be freely modified before the Config is used.
func DefaultConfig() Config {
	return Config{
		CheckInterval:     200 * time.Millisecond,
		SlowCheckInterval: 5 * time.Second,
		TimingMultiplier:  10.0,
		DebugMode:         false,
		LogFilePath:       "antidebug.log",
		OnDetect:          defaultOnDetect,
		DeferredMinDelay:  30 * time.Second,
		DeferredMaxDelay:  1 * time.Minute,
	}
}

var compromised int32

// IsCompromised reports whether any detection check has triggered since
// [Start] was called. It is safe to call concurrently from any number of
// goroutines.
//
// Once true, the result never resets. You can poll this in your own
// application logic to subtly alter behaviour — displaying misleading data,
// slowing responses, etc. — before the deferred [Config.OnDetect] callback
// fires, extending the false-hope effect.
//
// IsCompromised performs a single atomic load and is designed to be called on
// hot paths without measurable overhead.
func IsCompromised() bool {
	return atomic.LoadInt32(&compromised) == 1
}

// Start begins continuous background anti-debug monitoring using the provided
// [Config] and returns immediately. All checks run in background goroutines;
// your application continues normally.
//
// Start should be called once, as early as possible in main — ideally before
// any user-controlled input is processed — so that monitoring is live from the
// start of the process lifetime.
//
// When tampering is detected the process is NOT terminated immediately.
// Instead the package waits a random delay in
// [Config.DeferredMinDelay, Config.DeferredMaxDelay], then calls
// [Config.OnDetect] exactly once. During that window [IsCompromised] returns
// true and all goroutines keep running so the analyst observes no change.
//
// Calling Start more than once is not supported.
func Start(cfg Config) {
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 200 * time.Millisecond
	}
	if cfg.SlowCheckInterval <= 0 {
		cfg.SlowCheckInterval = 5 * time.Second
	}
	if cfg.TimingMultiplier <= 0 {
		cfg.TimingMultiplier = 10.0
	}
	if cfg.OnDetect == nil {
		cfg.OnDetect = defaultOnDetect
	}
	if cfg.DeferredMinDelay < 0 {
		cfg.DeferredMinDelay = 30 * time.Second
	}
	if cfg.DeferredMaxDelay < cfg.DeferredMinDelay {
		cfg.DeferredMaxDelay = cfg.DeferredMinDelay + 2*time.Minute
	}
	if cfg.LogFilePath == "" {
		cfg.LogFilePath = "antidebug.log"
	}

	logger := newLogger(cfg.DebugMode, cfg.LogFilePath)

	go runCheckLoop(cfg, logger, cfg.CheckInterval, buildFastChecks(cfg.TimingMultiplier))
	go runCheckLoop(cfg, logger, cfg.SlowCheckInterval, buildSlowChecks())
	go runSleepOverrun(cfg, logger)
}

func runSleepOverrun(cfg Config, log *debugLogger) {
	chk := checkSleepOverrun()
	for {
		reason, detected := chk()
		if detected {
			flagAndDefer(reason, cfg, log)
		}
	}
}

func runCheckLoop(cfg Config, log *debugLogger, interval time.Duration, checks []checkFunc) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		rand.Shuffle(len(checks), func(i, j int) { checks[i], checks[j] = checks[j], checks[i] })
		for _, chk := range checks {
			reason, detected := chk()
			if detected {
				flagAndDefer(reason, cfg, log)
			}
		}
	}
}

func flagAndDefer(reason string, cfg Config, log *debugLogger) {
	if atomic.CompareAndSwapInt32(&compromised, 0, 1) {
		log.write("DETECTED: " + reason)
		delay := cfg.DeferredMinDelay
		if cfg.DeferredMaxDelay > cfg.DeferredMinDelay {
			window := int64(cfg.DeferredMaxDelay - cfg.DeferredMinDelay)
			delay += time.Duration(rand.Int63n(window))
		}
		if delay == 0 {
			cfg.OnDetect(reason)
			return
		}
		go func() {
			time.Sleep(delay)
			cfg.OnDetect(reason)
		}()
	} else {
		log.write("ADDITIONAL HIT (already flagged): " + reason)
	}
}
