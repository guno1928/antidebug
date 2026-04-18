//go:build linux

package antidebug

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

func platformDiagnostics(sb *strings.Builder) {

	sb.WriteString("--- CPUID ---\n")
	_, _, ecx, _ := cpuid(1, 0)
	hypervisorBit := (ecx >> 31) & 1
	fmt.Fprintf(sb, "  Hypervisor bit (ECX[31]) : %d\n", hypervisorBit)
	_, ebx2, ecx2, edx2 := cpuid(0x40000000, 0)
	vendor := make([]byte, 12)
	*(*uint32)(unsafe.Pointer(&vendor[0])) = ebx2
	*(*uint32)(unsafe.Pointer(&vendor[4])) = ecx2
	*(*uint32)(unsafe.Pointer(&vendor[8])) = edx2
	fmt.Fprintf(sb, "  Hypervisor vendor string : %q\n", strings.TrimRight(string(vendor), "\x00"))

	sb.WriteString("--- /proc/self/status (key fields) ---\n")
	f, err := os.Open("/proc/self/status")
	if err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		wantFields := map[string]bool{
			"Pid:": true, "PPid:": true, "State:": true, "TracerPid:": true,
			"VmRSS:": true, "VmPeak:": true, "Threads:": true,
		}
		for scanner.Scan() {
			line := scanner.Text()
			for prefix := range wantFields {
				if strings.HasPrefix(line, prefix) {
					fmt.Fprintf(sb, "  %s\n", line)
					if prefix == "TracerPid:" {
						parts := strings.Fields(line)
						if len(parts) >= 2 {
							pid, err := strconv.Atoi(parts[1])
							if err == nil && pid != 0 {
								comm := readProcessComm(pid)
								fmt.Fprintf(sb, "    -> tracer comm: %q\n", comm)
							}
						}
					}
					break
				}
			}
		}
	} else {
		fmt.Fprintf(sb, "  (could not open /proc/self/status: %v)\n", err)
	}

	sb.WriteString("--- Parent process ---\n")
	ppid := os.Getppid()
	comm := readProcessComm(ppid)
	fmt.Fprintf(sb, "  Parent PID : %d  comm=%q\n", ppid, comm)

	sb.WriteString("--- Running processes (first 30) ---\n")
	entries, err := os.ReadDir("/proc")
	if err == nil {
		count := 0
		for _, e := range entries {
			if !e.IsDir() || count >= 30 {
				continue
			}
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			commData, err := os.ReadFile("/proc/" + e.Name() + "/comm")
			if err != nil {
				continue
			}
			procComm := strings.TrimSpace(string(commData))
			fmt.Fprintf(sb, "  PID %-6d  %s\n", pid, procComm)
			count++
		}
	}
}
