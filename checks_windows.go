//go:build windows

package antidebug

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	ntdll                          = syscall.NewLazyDLL("ntdll.dll")
	procIsDebuggerPresent          = kernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent = kernel32.NewProc("CheckRemoteDebuggerPresent")
	procNtQueryInformationProcess  = ntdll.NewProc("NtQueryInformationProcess")
	procNtQuerySystemInformation   = ntdll.NewProc("NtQuerySystemInformation")
	procOutputDebugStringA         = kernel32.NewProc("OutputDebugStringA")
	procCreateToolhelp32Snapshot   = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First             = kernel32.NewProc("Process32FirstW")
	procProcess32Next              = kernel32.NewProc("Process32NextW")
	procCloseHandle                = kernel32.NewProc("CloseHandle")
	procGetCurrentProcess          = kernel32.NewProc("GetCurrentProcess")
	procGetCurrentThread           = kernel32.NewProc("GetCurrentThread")
	procGetThreadContext           = kernel32.NewProc("GetThreadContext")
	procGetModuleHandleW           = kernel32.NewProc("GetModuleHandleW")
	procGetProcAddress             = kernel32.NewProc("GetProcAddress")
	procVirtualQuery               = kernel32.NewProc("VirtualQuery")
	procK32QueryWorkingSetEx       = kernel32.NewProc("K32QueryWorkingSetEx")
)

const (
	processDebugPort   = 7
	processDebugFlags  = 0x1f
	processDebugObject = 0x1e
	th32csSnapProcess  = 0x00000002
)

type processEntry32W struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [260]uint16
}

func platformFastChecks() []checkFunc {
	return []checkFunc{
		checkIsDebuggerPresent(),
		checkRemoteDebuggerPresent(),
		checkNtQueryDebugPort(),
		checkNtQueryDebugFlags(),
		checkNtQueryDebugObject(),
		checkPEBBeingDebugged(),
		checkPEBNtGlobalFlag(),
		checkHeapFlags(),
		checkParentProcess(),
		checkSandboxieDll(),
		checkSandboxieNtdllHooks(),
		checkHardwareBreakpoints(),
		checkKernelDebugger(),
		checkKUserSharedData(),
		checkDbgBreakPointPatched(),
		checkDbgUiRemoteBreakinPatched(),
		checkETWPatched(),
		checkAMSIPatched(),
	}
}

func platformSlowChecks() []checkFunc {
	return []checkFunc{
		checkRWXRegions(),
		checkPrivateExecutableRegions(),
	}
}

func checkIsDebuggerPresent() checkFunc {
	return func() (string, bool) {
		ret, _, _ := procIsDebuggerPresent.Call()
		if ret != 0 {
			return "IsDebuggerPresent returned true", true
		}
		return "", false
	}
}

func checkRemoteDebuggerPresent() checkFunc {
	return func() (string, bool) {
		hProc, _, _ := procGetCurrentProcess.Call()
		var isDebugged uint32
		procCheckRemoteDebuggerPresent.Call(hProc, uintptr(unsafe.Pointer(&isDebugged)))
		if isDebugged != 0 {
			return "CheckRemoteDebuggerPresent returned true", true
		}
		return "", false
	}
}

func checkNtQueryDebugPort() checkFunc {
	return func() (string, bool) {
		hProc, _, _ := procGetCurrentProcess.Call()
		var debugPort uintptr
		var returnLen uint32
		ret, _, _ := procNtQueryInformationProcess.Call(
			hProc,
			processDebugPort,
			uintptr(unsafe.Pointer(&debugPort)),
			unsafe.Sizeof(debugPort),
			uintptr(unsafe.Pointer(&returnLen)),
		)
		if ret == 0 && debugPort != 0 {
			return "NtQueryInformationProcess ProcessDebugPort is non-zero", true
		}
		return "", false
	}
}

func checkNtQueryDebugFlags() checkFunc {
	return func() (string, bool) {
		hProc, _, _ := procGetCurrentProcess.Call()
		var debugFlags uint32 = 1
		var returnLen uint32
		ret, _, _ := procNtQueryInformationProcess.Call(
			hProc,
			processDebugFlags,
			uintptr(unsafe.Pointer(&debugFlags)),
			unsafe.Sizeof(debugFlags),
			uintptr(unsafe.Pointer(&returnLen)),
		)
		if ret == 0 && debugFlags == 0 {
			return "NtQueryInformationProcess ProcessDebugFlags is 0 (debugged)", true
		}
		return "", false
	}
}

func checkNtQueryDebugObject() checkFunc {
	return func() (string, bool) {
		hProc, _, _ := procGetCurrentProcess.Call()
		var debugObject uintptr
		var returnLen uint32
		ret, _, _ := procNtQueryInformationProcess.Call(
			hProc,
			processDebugObject,
			uintptr(unsafe.Pointer(&debugObject)),
			unsafe.Sizeof(debugObject),
			uintptr(unsafe.Pointer(&returnLen)),
		)
		if ret == 0 && debugObject != 0 {
			return "NtQueryInformationProcess ProcessDebugObject is non-zero", true
		}
		return "", false
	}
}

func checkPEBBeingDebugged() checkFunc {
	return func() (string, bool) {
		type processBasicInfo struct {
			ExitStatus                   uintptr
			PebBaseAddress               uintptr
			AffinityMask                 uintptr
			BasePriority                 uintptr
			UniqueProcessID              uintptr
			InheritedFromUniqueProcessID uintptr
		}
		hProc, _, _ := procGetCurrentProcess.Call()
		var pbi processBasicInfo
		var retLen uint32
		ret, _, _ := procNtQueryInformationProcess.Call(
			hProc, 0,
			uintptr(unsafe.Pointer(&pbi)),
			unsafe.Sizeof(pbi),
			uintptr(unsafe.Pointer(&retLen)),
		)
		if ret != 0 || pbi.PebBaseAddress == 0 {
			return "", false
		}
		beingDebugged := *(*byte)(unsafe.Pointer(pbi.PebBaseAddress + 2))
		if beingDebugged != 0 {
			return "PEB BeingDebugged flag is set", true
		}
		return "", false
	}
}

func checkPEBNtGlobalFlag() checkFunc {
	return func() (string, bool) {
		type processBasicInfo struct {
			ExitStatus                   uintptr
			PebBaseAddress               uintptr
			AffinityMask                 uintptr
			BasePriority                 uintptr
			UniqueProcessID              uintptr
			InheritedFromUniqueProcessID uintptr
		}
		hProc, _, _ := procGetCurrentProcess.Call()
		var pbi processBasicInfo
		var retLen uint32
		ret, _, _ := procNtQueryInformationProcess.Call(
			hProc, 0,
			uintptr(unsafe.Pointer(&pbi)),
			unsafe.Sizeof(pbi),
			uintptr(unsafe.Pointer(&retLen)),
		)
		if ret != 0 || pbi.PebBaseAddress == 0 {
			return "", false
		}
		var ntGlobalFlag uint32
		if unsafe.Sizeof(uintptr(0)) == 8 {
			ntGlobalFlag = *(*uint32)(unsafe.Pointer(pbi.PebBaseAddress + 0xBC))
		} else {
			ntGlobalFlag = *(*uint32)(unsafe.Pointer(pbi.PebBaseAddress + 0x68))
		}
		if ntGlobalFlag&0x70 != 0 {
			return "PEB NtGlobalFlag has debugger flags set (0x70 mask)", true
		}
		return "", false
	}
}

func checkHeapFlags() checkFunc {
	return func() (string, bool) {
		type processBasicInfo struct {
			ExitStatus                   uintptr
			PebBaseAddress               uintptr
			AffinityMask                 uintptr
			BasePriority                 uintptr
			UniqueProcessID              uintptr
			InheritedFromUniqueProcessID uintptr
		}
		hProc, _, _ := procGetCurrentProcess.Call()
		var pbi processBasicInfo
		var retLen uint32
		ret, _, _ := procNtQueryInformationProcess.Call(
			hProc, 0,
			uintptr(unsafe.Pointer(&pbi)),
			unsafe.Sizeof(pbi),
			uintptr(unsafe.Pointer(&retLen)),
		)
		if ret != 0 || pbi.PebBaseAddress == 0 {
			return "", false
		}
		var processHeap uintptr
		if unsafe.Sizeof(uintptr(0)) == 8 {
			processHeap = *(*uintptr)(unsafe.Pointer(pbi.PebBaseAddress + 0x30))
		} else {
			processHeap = *(*uintptr)(unsafe.Pointer(pbi.PebBaseAddress + 0x18))
		}
		if processHeap == 0 {
			return "", false
		}
		var flags, forceFlags uint32
		if unsafe.Sizeof(uintptr(0)) == 8 {
			flags = *(*uint32)(unsafe.Pointer(processHeap + 0x70))
			forceFlags = *(*uint32)(unsafe.Pointer(processHeap + 0x74))
		} else {
			flags = *(*uint32)(unsafe.Pointer(processHeap + 0x40))
			forceFlags = *(*uint32)(unsafe.Pointer(processHeap + 0x44))
		}
		if flags&0x2 == 0 || forceFlags != 0 {
			return "process heap flags indicate debugger presence", true
		}
		return "", false
	}
}

func checkOutputDebugString() checkFunc {
	return func() (string, bool) {
		msg, _ := syscall.BytePtrFromString("a")
		syscall.GetLastError()
		procOutputDebugStringA.Call(uintptr(unsafe.Pointer(msg)))
		lastErr := syscall.GetLastError()
		if lastErr == syscall.Errno(0) {
			return "OutputDebugStringA GetLastError trick: debugger detected", true
		}
		return "", false
	}
}

func checkParentProcess() checkFunc {
	suspiciousParents := map[string]bool{
		"x64dbg.exe": true, "x32dbg.exe": true,
		"ollydbg.exe": true,
		"windbg.exe":  true, "kd.exe": true, "cdb.exe": true, "ntsd.exe": true,
		"ida.exe": true, "ida64.exe": true, "idaq.exe": true, "idaq64.exe": true,
		"dnspy.exe":         true,
		"processhacker.exe": true,
		"binaryninja.exe":   true,
		"radare2.exe":       true, "r2.exe": true,
		"cutter.exe":           true,
		"pestudio.exe":         true,
		"apimonitor.exe":       true,
		"fiddler.exe":          true,
		"immunitydebugger.exe": true,
	}
	return func() (string, bool) {
		ppid := os.Getppid()
		parentName := processNameByPID(uint32(ppid))
		if parentName == "" {
			return "", false
		}
		if suspiciousParents[strings.ToLower(parentName)] {
			return "parent process is a known analysis tool: " + parentName, true
		}
		return "", false
	}
}

func checkSandboxieDll() checkFunc {
	return func() (string, bool) {
		name, _ := syscall.UTF16PtrFromString("SbieDll.dll")
		h, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(name)))
		if h != 0 {
			return "Sandboxie: SbieDll.dll is mapped into this process", true
		}
		if os.Getenv("SBIE_PROCESS") != "" {
			return "Sandboxie: SBIE_PROCESS environment variable is set", true
		}
		return "", false
	}
}

func checkSandboxieNtdllHooks() checkFunc {
	ntdllName, _ := syscall.UTF16PtrFromString("ntdll.dll")
	ntdllHandle, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName)))
	sbieDllName, _ := syscall.UTF16PtrFromString("SbieDll.dll")

	hookedFns := []string{
		"NtCreateFile", "NtOpenFile",
		"NtCreateKey", "NtOpenKey",
		"NtCreateProcess", "NtCreateProcessEx",
		"NtCreateSection",
	}

	return func() (string, bool) {
		if ntdllHandle == 0 {
			return "", false
		}
		sbieHandle, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(sbieDllName)))
		if sbieHandle == 0 {
			return "", false
		}
		for _, fn := range hookedFns {
			fnPtr, err := syscall.BytePtrFromString(fn)
			if err != nil {
				continue
			}
			addr, _, _ := procGetProcAddress.Call(ntdllHandle, uintptr(unsafe.Pointer(fnPtr)))
			if addr == 0 {
				continue
			}
			b := (*[12]byte)(unsafe.Pointer(addr))
			if b[0] == 0xE9 {
				return "Sandboxie: NTDLL!" + fn + " has JMP rel32 hook (Sandboxie trampoline)", true
			}
			if b[0] == 0x48 && b[1] == 0xB8 {
				if b[10] == 0xFF && b[11] == 0xE0 {
					return "Sandboxie: NTDLL!" + fn + " has MOV RAX/JMP hook (Sandboxie trampoline)", true
				}
			}
		}
		return "", false
	}
}

func checkNtdllInlineHooks() checkFunc {
	ntdllName, _ := syscall.UTF16PtrFromString("ntdll.dll")
	ntdllHandle, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName)))

	targets := []string{
		"NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile",
		"NtCreateKey", "NtOpenKey", "NtDeleteKey", "NtSetValueKey",
		"NtCreateProcess", "NtCreateProcessEx", "NtCreateUserProcess",
		"NtCreateThread", "NtCreateThreadEx", "NtResumeThread",
		"NtAllocateVirtualMemory", "NtFreeVirtualMemory",
		"NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtReadVirtualMemory",
		"NtMapViewOfSection", "NtUnmapViewOfSection", "NtCreateSection",
		"NtQuerySystemInformation", "NtQueryInformationProcess",
		"NtSetInformationThread", "NtQueryObject",
		"LdrLoadDll", "LdrGetProcedureAddress",
	}

	return func() (string, bool) {
		if ntdllHandle == 0 {
			return "", false
		}
		for _, fn := range targets {
			fnPtr, err := syscall.BytePtrFromString(fn)
			if err != nil {
				continue
			}
			addr, _, _ := procGetProcAddress.Call(ntdllHandle, uintptr(unsafe.Pointer(fnPtr)))
			if addr == 0 {
				continue
			}
			b := (*[12]byte)(unsafe.Pointer(addr))
			if b[0] == 0xE9 {
				return "NTDLL!" + fn + " has JMP rel32 inline hook (hooking framework detected)", true
			}
			if b[0] == 0xFF && b[1] == 0x25 {
				return "NTDLL!" + fn + " has JMP [mem] inline hook (hooking framework detected)", true
			}
			if b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0 {
				return "NTDLL!" + fn + " has MOV RAX/JMP RAX inline hook (Frida/manual hook detected)", true
			}
			if b[0] == 0x68 && b[5] == 0xC3 {
				return "NTDLL!" + fn + " has PUSH/RET inline hook (hooking framework detected)", true
			}
		}
		return "", false
	}
}

func checkRWXRegions() checkFunc {
	type memBasicInfo struct {
		BaseAddress       uintptr
		AllocationBase    uintptr
		AllocationProtect uint32
		_                 uint32
		RegionSize        uintptr
		State             uint32
		Protect           uint32
		Type              uint32
	}
	const (
		memCommit      = 0x1000
		pageExecRW     = 0x40
		pageExecRWCopy = 0x80
	)

	return func() (string, bool) {
		var addr uintptr
		var mbi memBasicInfo
		sz := unsafe.Sizeof(mbi)
		for {
			ret, _, _ := procVirtualQuery.Call(addr, uintptr(unsafe.Pointer(&mbi)), sz)
			if ret == 0 {
				break
			}
			if mbi.State == memCommit && (mbi.Protect == pageExecRW || mbi.Protect == pageExecRWCopy) {
				return "RWX memory region in process (hook injection): base=0x" + uintptrHex(mbi.BaseAddress), true
			}
			next := mbi.BaseAddress + mbi.RegionSize
			if next <= addr {
				break
			}
			addr = next
		}
		return "", false
	}
}

func uintptrHex(p uintptr) string {
	const h = "0123456789ABCDEF"
	if p == 0 {
		return "0"
	}
	var buf [16]byte
	i := 16
	for p != 0 {
		i--
		buf[i] = h[p&0xF]
		p >>= 4
	}
	return string(buf[i:])
}

func checkHardwareBreakpoints() checkFunc {
	type context struct {
		_            [6]uint64
		ContextFlags uint32
		MxCsr        uint32
	}
	_ = context{}

	const contextDebugRegisters = 0x00100010

	const (
		dr0Offset = 72
		dr1Offset = 80
		dr2Offset = 88
		dr3Offset = 96
		ctxSize   = 1232
	)

	return func() (string, bool) {
		raw := make([]byte, ctxSize+16)
		aligned := uintptr(unsafe.Pointer(&raw[0]))
		if aligned&0xF != 0 {
			aligned = (aligned + 15) &^ 15
		}
		*(*uint32)(unsafe.Pointer(aligned + 48)) = contextDebugRegisters
		hThread, _, _ := procGetCurrentThread.Call()
		ret, _, _ := procGetThreadContext.Call(hThread, aligned)
		if ret == 0 {
			return "", false
		}
		dr0 := *(*uint64)(unsafe.Pointer(aligned + dr0Offset))
		dr1 := *(*uint64)(unsafe.Pointer(aligned + dr1Offset))
		dr2 := *(*uint64)(unsafe.Pointer(aligned + dr2Offset))
		dr3 := *(*uint64)(unsafe.Pointer(aligned + dr3Offset))
		if dr0 != 0 || dr1 != 0 || dr2 != 0 || dr3 != 0 {
			return "hardware breakpoint registers DR0-DR3 are non-zero (debugger detected)", true
		}
		return "", false
	}
}

func checkKernelDebugger() checkFunc {
	const systemKernelDebuggerInformation = 0x23
	type kernelDebuggerInfo struct {
		DebuggerEnabled    byte
		DebuggerNotPresent byte
	}
	return func() (string, bool) {
		var info kernelDebuggerInfo
		ret, _, _ := procNtQuerySystemInformation.Call(
			systemKernelDebuggerInformation,
			uintptr(unsafe.Pointer(&info)),
			unsafe.Sizeof(info),
			0,
		)
		if ret == 0 && info.DebuggerEnabled != 0 && info.DebuggerNotPresent == 0 {
			return "NtQuerySystemInformation reports kernel debugger is active", true
		}
		return "", false
	}
}

func checkKUserSharedData() checkFunc {
	return func() (string, bool) {
		b := *(*byte)(unsafe.Pointer(uintptr(0x7FFE02D4)))
		if b&0x01 != 0 && b&0x02 == 0 {
			return "KUSER_SHARED_DATA KdDebuggerEnabled is set (kernel debugger active)", true
		}
		return "", false
	}
}

func checkDbgBreakPointPatched() checkFunc {
	ntdllName, _ := syscall.UTF16PtrFromString("ntdll.dll")
	ntdllHandle, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName)))
	return func() (string, bool) {
		if ntdllHandle == 0 {
			return "", false
		}
		fnPtr, _ := syscall.BytePtrFromString("DbgBreakPoint")
		addr, _, _ := procGetProcAddress.Call(ntdllHandle, uintptr(unsafe.Pointer(fnPtr)))
		if addr == 0 {
			return "", false
		}
		b := *(*byte)(unsafe.Pointer(addr))
		if b != 0xCC {
			return "ntdll!DbgBreakPoint has been patched (byte=0x" + byteHex(b) + ") — debugger attach prevention or hook", true
		}
		return "", false
	}
}

func checkDbgUiRemoteBreakinPatched() checkFunc {
	ntdllName, _ := syscall.UTF16PtrFromString("ntdll.dll")
	ntdllHandle, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName)))
	return func() (string, bool) {
		if ntdllHandle == 0 {
			return "", false
		}
		fnPtr, _ := syscall.BytePtrFromString("DbgUiRemoteBreakin")
		addr, _, _ := procGetProcAddress.Call(ntdllHandle, uintptr(unsafe.Pointer(fnPtr)))
		if addr == 0 {
			return "", false
		}
		b0 := *(*byte)(unsafe.Pointer(addr))
		if b0 == 0xC3 || b0 == 0xE9 || b0 == 0xEB {
			return "ntdll!DbgUiRemoteBreakin patched (first byte 0x" + byteHex(b0) + ") — anti-attach or injection detected", true
		}
		return "", false
	}
}

func checkETWPatched() checkFunc {
	ntdllName, _ := syscall.UTF16PtrFromString("ntdll.dll")
	ntdllHandle, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName)))
	return func() (string, bool) {
		if ntdllHandle == 0 {
			return "", false
		}
		for _, fn := range []string{"EtwEventWrite", "EtwEventWriteFull"} {
			fnPtr, _ := syscall.BytePtrFromString(fn)
			addr, _, _ := procGetProcAddress.Call(ntdllHandle, uintptr(unsafe.Pointer(fnPtr)))
			if addr == 0 {
				continue
			}
			b := *(*byte)(unsafe.Pointer(addr))
			if b == 0xC3 || b == 0xEB || b == 0xE9 {
				return "ntdll!" + fn + " is patched (ETW disabled by attacker — byte=0x" + byteHex(b) + ")", true
			}
		}
		return "", false
	}
}

func checkAMSIPatched() checkFunc {
	amsiName, _ := syscall.UTF16PtrFromString("amsi.dll")
	return func() (string, bool) {
		amsiHandle, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(amsiName)))
		if amsiHandle == 0 {
			return "", false
		}
		for _, fn := range []string{"AmsiScanBuffer", "AmsiOpenSession"} {
			fnPtr, _ := syscall.BytePtrFromString(fn)
			addr, _, _ := procGetProcAddress.Call(amsiHandle, uintptr(unsafe.Pointer(fnPtr)))
			if addr == 0 {
				continue
			}
			b := (*[3]byte)(unsafe.Pointer(addr))
			if b[0] == 0xC3 || b[0] == 0xEB || b[0] == 0xE9 {
				return "amsi.dll!" + fn + " is patched (AMSI bypass detected — byte=0x" + byteHex(b[0]) + ")", true
			}
			if b[0] == 0xB8 && b[2] == 0x07 {
				return "amsi.dll!" + fn + " appears to return hardcoded error (AMSI bypass)", true
			}
		}
		return "", false
	}
}

func checkPrivateExecutableRegions() checkFunc {
	type memBasicInfo struct {
		BaseAddress       uintptr
		AllocationBase    uintptr
		AllocationProtect uint32
		_                 uint32
		RegionSize        uintptr
		State             uint32
		Protect           uint32
		Type              uint32
	}
	const (
		memCommit   = 0x1000
		memPrivate  = 0x20000
		memImage    = 0x1000000
		pageExec    = 0x10
		pageExecR   = 0x20
		pageExecRW  = 0x40
		pageExecRWC = 0x80
		minAddress  = uintptr(0x10000)
		minSize     = uintptr(4096)
	)
	return func() (string, bool) {
		var addr uintptr = minAddress
		var mbi memBasicInfo
		sz := unsafe.Sizeof(mbi)
		for {
			ret, _, _ := procVirtualQuery.Call(addr, uintptr(unsafe.Pointer(&mbi)), sz)
			if ret == 0 {
				break
			}
			if mbi.State == memCommit && mbi.Type == memPrivate && mbi.RegionSize >= minSize {
				p := mbi.Protect & 0xFF
				if p == pageExec || p == pageExecR || p == pageExecRW || p == pageExecRWC {
					return "private executable memory region (injected code/beacon): base=0x" + uintptrHex(mbi.BaseAddress) + " size=" + uintptrHex(mbi.RegionSize), true
				}
			}
			next := mbi.BaseAddress + mbi.RegionSize
			if next <= addr {
				break
			}
			addr = next
		}
		return "", false
	}
}

func checkNtdllPagePrivate() checkFunc {
	ntdllName, _ := syscall.UTF16PtrFromString("ntdll.dll")

	type wsExInfo struct {
		VirtualAddress    uintptr
		VirtualAttributes uintptr
	}

	return func() (string, bool) {
		ntdllBase, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName)))
		if ntdllBase == 0 {
			return "", false
		}
		dosHdr := (*[2]byte)(unsafe.Pointer(ntdllBase))
		if dosHdr[0] != 'M' || dosHdr[1] != 'Z' {
			return "", false
		}
		peOffset := *(*uint32)(unsafe.Pointer(ntdllBase + 0x3C))
		peBase := ntdllBase + uintptr(peOffset)
		sig := *(*uint32)(unsafe.Pointer(peBase))
		if sig != 0x00004550 {
			return "", false
		}
		numSections := *(*uint16)(unsafe.Pointer(peBase + 6))
		optHdrSize := *(*uint16)(unsafe.Pointer(peBase + 20))
		sectionBase := peBase + 24 + uintptr(optHdrSize)

		textVA := uintptr(0)
		for i := uintptr(0); i < uintptr(numSections); i++ {
			sec := sectionBase + i*40
			name := (*[8]byte)(unsafe.Pointer(sec))
			if name[0] == '.' && name[1] == 't' && name[2] == 'e' && name[3] == 'x' && name[4] == 't' {
				va := *(*uint32)(unsafe.Pointer(sec + 12))
				textVA = ntdllBase + uintptr(va)
				break
			}
		}
		if textVA == 0 {
			textVA = ntdllBase
		}

		info := wsExInfo{VirtualAddress: textVA}
		ret, _, _ := procK32QueryWorkingSetEx.Call(
			^uintptr(0),
			uintptr(unsafe.Pointer(&info)),
			unsafe.Sizeof(info),
		)
		if ret == 0 {
			return "", false
		}
		attrs := info.VirtualAttributes
		valid := attrs & 1
		shared := (attrs >> 15) & 1
		if valid == 1 && shared == 0 {
			return "ntdll.dll .text page is private (copy-on-write: hook was written to ntdll code)", true
		}
		return "", false
	}
}

func byteHex(b byte) string {
	const h = "0123456789ABCDEF"
	return string([]byte{h[b>>4], h[b&0xF]})
}

func processNameByPID(pid uint32) string {
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snapshot == ^uintptr(0) {
		return ""
	}
	defer procCloseHandle.Call(snapshot)

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	for ret != 0 {
		if entry.ProcessID == pid {
			return syscall.UTF16ToString(entry.ExeFile[:])
		}
		ret, _, _ = procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	}
	return ""
}
