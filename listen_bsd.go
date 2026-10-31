//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package wisp

import "syscall"

// listenControl sets SO_REUSEPORT on the listening socket of Listen (see
// listen_linux.go; the other options are Linux's).
func listenControl(_, _ string, c syscall.RawConn) error {
	var err error
	cerr := c.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
	})
	if cerr != nil {
		return cerr
	}
	return err
}
