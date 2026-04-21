package antidebug

import "syscall"

func defaultOnDetect(_ string) {
	syscall.Exit(1)
}
