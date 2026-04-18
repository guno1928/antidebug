//go:build windows

package antidebug

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const hkeyLocalMachine uintptr = 0x80000002

func registryKeyExists(root uintptr, subkey string) bool {
	subkeyPtr, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return false
	}
	var hKey uintptr
	regOpenKeyEx := syscall.NewLazyDLL("advapi32.dll").NewProc("RegOpenKeyExW")
	regCloseKey := syscall.NewLazyDLL("advapi32.dll").NewProc("RegCloseKey")
	ret, _, _ := regOpenKeyEx.Call(root, uintptr(unsafe.Pointer(subkeyPtr)), 0, 0x20019, uintptr(unsafe.Pointer(&hKey)))
	if ret == 0 {
		regCloseKey.Call(hKey)
		return true
	}
	return false
}

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

	sb.WriteString("--- Windows debug state ---\n")
	r, _, _ := procIsDebuggerPresent.Call()
	fmt.Fprintf(sb, "  IsDebuggerPresent        : %d\n", r)
	hProc, _, _ := procGetCurrentProcess.Call()
	var isRemote uint32
	procCheckRemoteDebuggerPresent.Call(hProc, uintptr(unsafe.Pointer(&isRemote)))
	fmt.Fprintf(sb, "  RemoteDebuggerPresent    : %d\n", isRemote)
	var debugPort uintptr
	var retLen uint32
	procNtQueryInformationProcess.Call(hProc, processDebugPort,
		uintptr(unsafe.Pointer(&debugPort)), unsafe.Sizeof(debugPort),
		uintptr(unsafe.Pointer(&retLen)))
	fmt.Fprintf(sb, "  NtQuery DebugPort        : %d\n", debugPort)
	var debugFlags uint32 = 1
	procNtQueryInformationProcess.Call(hProc, processDebugFlags,
		uintptr(unsafe.Pointer(&debugFlags)), unsafe.Sizeof(debugFlags),
		uintptr(unsafe.Pointer(&retLen)))
	fmt.Fprintf(sb, "  NtQuery DebugFlags       : %d  (0 = debugged)\n", debugFlags)

	// ── Sandboxie ─────────────────────────────────────────────────────────
	sb.WriteString("--- Sandboxie ---\n")
	sbiePtr, _ := syscall.UTF16PtrFromString("SbieDll.dll")
	h, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(sbiePtr)))
	fmt.Fprintf(sb, "  SbieDll.dll in process        : %v (handle=0x%X)\n", h != 0, h)
	sbieProc := os.Getenv("SBIE_PROCESS")
	if sbieProc == "" {
		sbieProc = "<not set>"
	}
	fmt.Fprintf(sb, "  SBIE_PROCESS env var          : %s\n", sbieProc)

	ntdllName2, _ := syscall.UTF16PtrFromString("ntdll.dll")
	ntdllH, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName2)))
	sb.WriteString("  NTDLL function prologues:\n")
	for _, fn := range []string{"NtCreateFile", "NtOpenFile", "NtCreateKey", "NtCreateProcess"} {
		fnPtr, err := syscall.BytePtrFromString(fn)
		if err != nil || ntdllH == 0 {
			continue
		}
		addr, _, _ := procGetProcAddress.Call(ntdllH, uintptr(unsafe.Pointer(fnPtr)))
		if addr == 0 {
			continue
		}
		b := (*[5]byte)(unsafe.Pointer(addr))
		fmt.Fprintf(sb, "    %-26s : %02X %02X %02X %02X %02X\n", fn, b[0], b[1], b[2], b[3], b[4])
	}

	// ── Registry keys ─────────────────────────────────────────────────────
	sb.WriteString("--- Registry keys (HKLM) ---\n")
	keysToCheck := []string{
		`SOFTWARE\Oracle\VirtualBox Guest Additions`,
		`SOFTWARE\VMware, Inc.\VMware Tools`,
		`HARDWARE\ACPI\DSDT\VBOX__`,
		`SYSTEM\ControlSet001\Services\VBoxGuest`,
		`SOFTWARE\Wine`,
		`SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`,
	}
	for _, key := range keysToCheck {
		exists := registryKeyExists(hkeyLocalMachine, key)
		fmt.Fprintf(sb, "  %-55s : %v\n", key, exists)
	}

	// ── Parent process ─────────────────────────────────────────────────────
	sb.WriteString("--- Parent process ---\n")
	myPID := uint32(os.Getpid())
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snapshot != ^uintptr(0) {
		var entry processEntry32W
		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		for ret != 0 {
			if entry.ProcessID == myPID {
				parentName := processNameByPID(entry.ParentProcessID)
				fmt.Fprintf(sb, "  Parent PID : %d (%s)\n", entry.ParentProcessID, parentName)
				break
			}
			ret, _, _ = procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		}
		procCloseHandle.Call(snapshot)
	}

	sb.WriteString("--- Running processes (first 30) ---\n")
	snap2, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap2 != ^uintptr(0) {
		defer procCloseHandle.Call(snap2)
		var entry processEntry32W
		entry.Size = uint32(unsafe.Sizeof(entry))
		count := 0
		ret, _, _ := procProcess32First.Call(snap2, uintptr(unsafe.Pointer(&entry)))
		for ret != 0 && count < 30 {
			name := syscall.UTF16ToString(entry.ExeFile[:])
			fmt.Fprintf(sb, "  PID %-6d  %s\n", entry.ProcessID, name)
			ret, _, _ = procProcess32Next.Call(snap2, uintptr(unsafe.Pointer(&entry)))
			count++
		}
	}
}
