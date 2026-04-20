package antidebug

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

// Diagnostics returns a formatted multi-line string describing the system
// environment as observed by the antidebug package. The output includes:
//
//   - OS, architecture, CPU count, and hostname
//   - All network interface names, MAC addresses, and OUI prefixes
//   - Relevant environment variables (sandbox markers, TEMP paths, shell info)
//   - Platform-specific debug and VM state (Windows: IsDebuggerPresent, PEB
//     flags, NtQuery results, Sandboxie DLL, running processes, registry VM
//     keys; Linux: /proc/self/status fields, TracerPid, parent process comm)
//   - CPUID hypervisor vendor string
//
// Diagnostics is intended for troubleshooting false positives: collect the
// output on a clean reference machine and on the machine that triggered a
// detection, then diff the two to identify the environmental difference.
//
// It has no effect on monitoring state and may be called at any time, even
// before [Start].
func Diagnostics() string {
	var sb strings.Builder

	sb.WriteString("=== antidebug diagnostics ===\n")
	fmt.Fprintf(&sb, "OS/Arch  : %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&sb, "CPUs     : %d\n", runtime.NumCPU())
	hostname, _ := os.Hostname()
	fmt.Fprintf(&sb, "Hostname : %s\n", hostname)

	sb.WriteString("--- Network interfaces ---\n")
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		mac := iface.HardwareAddr
		oui := "(no hw addr)"
		if len(mac) >= 3 {
			oui = fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2])
		}
		fmt.Fprintf(&sb, "  %-20s mac=%-17s OUI=%s flags=%v\n",
			iface.Name, mac.String(), oui, iface.Flags)
	}

	sb.WriteString("--- Environment variables ---\n")
	interestingVars := []string{
		"COMPUTERNAME", "USERNAME", "USER", "HOME",
		"SANDBOXIE", "SANDBOXIE_INSTALL_DIR", "SBIE_PROCESS",
		"CUCKOO", "CAPE", "ANY_RUN",
		"TEMP", "TMP",
		"TERM", "SHELL",
	}
	found := false
	for _, v := range interestingVars {
		if val := os.Getenv(v); val != "" {
			fmt.Fprintf(&sb, "  %s=%s\n", v, val)
			found = true
		}
	}
	if !found {
		sb.WriteString("  (none of the tracked vars are set)\n")
	}

	platformDiagnostics(&sb)

	sb.WriteString("=== end diagnostics ===\n")
	return sb.String()
}
