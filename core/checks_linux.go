//go:build linux

package antidebug

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func platformFastChecks() []checkFunc {
	return []checkFunc{
		checkProcStatusTracerPid(),
		checkProcStatusState(),
		checkLDPreload(),
		checkSeccomp(),
	}
}

func platformSlowChecks() []checkFunc {
	return []checkFunc{
		checkLinuxRWXRegions(),
		checkLinuxInjectedLibraries(),
		checkAnonymousExecutableRegions(),
		checkLinuxSelfExeIntegrity(),
	}
}

func checkProcStatusTracerPid() checkFunc {
	knownDebuggers := map[string]bool{
		"gdb": true, "gdb-multiarch": true,
		"lldb": true, "lldb-server": true, "debugserver": true,
		"strace": true, "ltrace": true,
		"radare2": true, "r2": true,
		"frida": true, "frida-server": true, "frida-gadget": true,
		"gdbserver": true,
		"rr":        true,
	}
	return func() (string, bool) {
		f, err := os.Open("/proc/self/status")
		if err != nil {
			return "", false
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "TracerPid:") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 2 {
				break
			}
			pid, err := strconv.Atoi(parts[1])
			if err != nil || pid == 0 {
				break
			}
			tracerComm := readProcessComm(pid)
			if knownDebuggers[tracerComm] {
				return "/proc/self/status TracerPid=" + parts[1] + " comm=" + tracerComm + " (known debugger)", true
			}
			break
		}
		return "", false
	}
}

func readProcessComm(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(string(data)))
}

func checkProcStatusState() checkFunc {
	return func() (string, bool) {
		f, err := os.Open("/proc/self/status")
		if err != nil {
			return "", false
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "State:") {
				lower := strings.ToLower(line)
				if strings.Contains(lower, "tracing stop") || strings.Contains(lower, "\tt ") {
					return "/proc/self/status State is tracing stop", true
				}
				break
			}
		}
		return "", false
	}
}

func checkLinuxRWXRegions() checkFunc {
	return func() (string, bool) {
		f, err := os.Open("/proc/self/maps")
		if err != nil {
			return "", false
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if len(line) < 20 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			perms := fields[1]
			if len(perms) < 3 {
				continue
			}
			if perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x' {
				pathname := ""
				if len(fields) >= 6 {
					pathname = fields[5]
				}
				if pathname == "" {
					pathname = "<anonymous>"
				}
				return "rwx memory region detected (hook injection): " + fields[0] + " " + pathname, true
			}
		}
		return "", false
	}
}

func checkLinuxInjectedLibraries() checkFunc {
	baseline := make(map[string]bool)
	if f, err := os.Open("/proc/self/maps"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			path := fields[5]
			if strings.HasSuffix(path, ".so") || strings.Contains(path, ".so.") {
				baseline[path] = true
			}
		}
		f.Close()
	}

	runtimeAllowed := map[string]bool{
		"/lib/x86_64-linux-gnu/libnss_files.so.2":   true,
		"/lib/x86_64-linux-gnu/libnss_dns.so.2":     true,
		"/usr/lib/x86_64-linux-gnu/libnss_files.so": true,
		"/usr/lib/x86_64-linux-gnu/libnss_dns.so":   true,
		"/lib/x86_64-linux-gnu/libpam.so.0":         true,
	}

	return func() (string, bool) {
		f, err := os.Open("/proc/self/maps")
		if err != nil {
			return "", false
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			path := fields[5]
			if !(strings.HasSuffix(path, ".so") || strings.Contains(path, ".so.")) {
				continue
			}
			if !baseline[path] && !runtimeAllowed[path] {
				return "unexpected shared library injected into process: " + path, true
			}
		}
		return "", false
	}
}

func checkLDPreload() checkFunc {
	baseline := os.Getenv("LD_PRELOAD")
	return func() (string, bool) {
		current := os.Getenv("LD_PRELOAD")
		if current == "" {
			return "", false
		}
		if baseline != "" {
			if current != baseline {
				return "LD_PRELOAD changed after startup (library injection): " + current, true
			}
			return "", false
		}
		return "LD_PRELOAD is set (library injection / hook framework): " + current, true
	}
}

func checkSeccomp() checkFunc {
	return func() (string, bool) {
		f, err := os.Open("/proc/self/status")
		if err != nil {
			return "", false
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "Seccomp:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				break
			}
			val, err := strconv.Atoi(fields[1])
			if err != nil {
				break
			}
			if val == 1 {
				return "/proc/self/status Seccomp=1 (SECCOMP_STRICT: process sandboxed)", true
			}
			if val == 2 {
				return "/proc/self/status Seccomp=2 (SECCOMP_FILTER: BPF filter applied by sandbox)", true
			}
			break
		}
		return "", false
	}
}

func checkAnonymousExecutableRegions() checkFunc {
	knownPseudo := map[string]bool{
		"[vdso]": true, "[vsyscall]": true,
		"[vvar]": true, "[stack]": true, "[heap]": true,
	}
	return func() (string, bool) {
		f, err := os.Open("/proc/self/maps")
		if err != nil {
			return "", false
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			perms := fields[1]
			if len(perms) < 3 || perms[2] != 'x' {
				continue
			}
			if len(fields) >= 6 {
				path := fields[5]
				if knownPseudo[path] {
					continue
				}
				if len(path) > 0 && path[0] == '/' {
					continue
				}
			}
			return "anonymous executable memory region (injected shellcode): " + fields[0] + " perms=" + perms, true
		}
		return "", false
	}
}

func checkLinuxSelfExeIntegrity() checkFunc {
	baseExe, _ := os.Readlink("/proc/self/exe")
	return func() (string, bool) {
		exePath, err := os.Readlink("/proc/self/exe")
		if err != nil {
			return "/proc/self/exe unreadable (fileless/memfd execution?)", true
		}
		if strings.Contains(exePath, " (deleted)") {
			return "/proc/self/exe points to deleted file (fileless execution): " + exePath, true
		}
		if strings.HasPrefix(exePath, "/proc/") || strings.HasPrefix(exePath, "/memfd:") {
			return "/proc/self/exe points to in-memory fd (fileless/injection): " + exePath, true
		}
		if baseExe != "" && exePath != baseExe {
			return "/proc/self/exe changed after startup: was=" + baseExe + " now=" + exePath, true
		}
		f2, err := os.Open(exePath)
		if err != nil {
			return "/proc/self/exe cannot be opened: " + err.Error(), true
		}
		defer f2.Close()
		var magic [4]byte
		if _, err := f2.Read(magic[:]); err != nil {
			return "/proc/self/exe magic read failed: " + err.Error(), true
		}
		if magic[0] != 0x7F || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F' {
			return "/proc/self/exe ELF magic invalid (executable tampered)", true
		}
		return "", false
	}
}
