package antidebug

import (
	"crypto/sha256"
	"fmt"
	"time"
)

type checkFunc func() (reason string, detected bool)

func buildFastChecks(multiplier float64) []checkFunc {
	checks := []checkFunc{
		checkSleepAccuracy(),
		checkHashTiming(multiplier),
	}
	checks = append(checks, platformFastChecks()...)
	return checks
}

func buildSlowChecks() []checkFunc {
	return platformSlowChecks()
}

func checkSleepAccuracy() checkFunc {
	return func() (string, bool) {
		target := time.Millisecond
		t0 := time.Now()
		time.Sleep(target)
		elapsed := time.Since(t0)
		if elapsed < 100*time.Microsecond {
			return "sleep accelerated — likely sandbox clock manipulation", true
		}
		return "", false
	}
}

func checkSleepOverrun() checkFunc {
	const sleepTarget = 2 * time.Second
	const maxAllowed = 8 * time.Second

	return func() (string, bool) {
		t0 := time.Now()
		time.Sleep(sleepTarget)
		elapsedNs := time.Since(t0).Nanoseconds()
		if elapsedNs >= maxAllowed.Nanoseconds() {
			return fmt.Sprintf("sleep overrun detected: expected ~2s, got %dns — process was paused by debugger", elapsedNs), true
		}
		return "", false
	}
}

func checkHashTiming(multiplier float64) checkFunc {
	buf := make([]byte, 4096)
	const windowSize = 20
	const warmupSamples = 10
	samples := make([]int64, 0, windowSize)
	calls := 0

	for i := 0; i < 3; i++ {
		t0 := time.Now()
		for j := 0; j < 100; j++ {
			sha256.Sum256(buf)
		}
		samples = append(samples, time.Since(t0).Nanoseconds())
	}

	rollingMin := func() int64 {
		min := samples[0]
		for _, s := range samples[1:] {
			if s < min {
				min = s
			}
		}
		return min
	}

	consecutiveHits := 0
	const requiredConsecutive = 5

	return func() (string, bool) {
		t0 := time.Now()
		for i := 0; i < 100; i++ {
			sha256.Sum256(buf)
		}
		elapsed := time.Since(t0).Nanoseconds()
		calls++

		if len(samples) < windowSize {
			samples = append(samples, elapsed)
		} else {
			samples[(calls-1)%windowSize] = elapsed
		}

		if calls <= warmupSamples {
			consecutiveHits = 0
			return "", false
		}

		baseline := rollingMin()
		threshold := int64(float64(baseline) * multiplier)
		if elapsed > threshold {
			consecutiveHits++
			if consecutiveHits >= requiredConsecutive {
				consecutiveHits = 0
				return "hash computation timing anomaly (debugger step overhead)", true
			}
		} else {
			consecutiveHits = 0
		}
		return "", false
	}
}
