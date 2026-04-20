package antidebug

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type debugLogger struct {
	enabled  bool
	filePath string
	mu       sync.Mutex
	file     *os.File
	pool     sync.Pool
}

func newLogger(enabled bool, path string) *debugLogger {
	l := &debugLogger{
		enabled:  enabled,
		filePath: path,
	}
	l.pool = sync.Pool{
		New: func() any {
			buf := make([]byte, 0, 256)
			return &buf
		},
	}
	if enabled {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err == nil {
			l.file = f
		}
	}
	return l
}

func (l *debugLogger) write(msg string) {
	if !l.enabled || l.file == nil {
		return
	}
	bufPtr := l.pool.Get().(*[]byte)
	buf := (*bufPtr)[:0]
	buf = fmt.Appendf(buf, "[%s] %s\n", time.Now().Format(time.RFC3339), msg)
	l.mu.Lock()
	l.file.Write(buf)
	l.mu.Unlock()
	*bufPtr = buf
	l.pool.Put(bufPtr)
}
