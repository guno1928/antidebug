package antidebug

import "os"

func defaultOnDetect(_ string) {
	os.Exit(1)
}
