//go:build linux

package antidebug

func cpuid(leaf, subLeaf uint32) (eax, ebx, ecx, edx uint32)
