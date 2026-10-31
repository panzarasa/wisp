//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package wisp

import "syscall"

// listenControl sets no option where SO_REUSEPORT is not available.
func listenControl(_, _ string, _ syscall.RawConn) error {
	return nil
}
