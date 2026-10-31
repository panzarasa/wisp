package wisp

import "syscall"

const (
	soReusePort = 0x0F // SO_REUSEPORT
	tcpFastOpen = 0x17 // TCP_FASTOPEN
)

// listenControl sets the options of the listening socket of Listen, as
// maurice2k/tcpserver does: SO_REUSEPORT; TCP_FASTOPEN, which lets a
// returning client send its first bytes with the SYN; TCP_DEFER_ACCEPT,
// which wakes the server only once the client has sent something. Only
// SO_REUSEPORT is required: the others are optimizations a kernel may lack.
func listenControl(_, _ string, c syscall.RawConn) error {
	var err error
	cerr := c.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpFastOpen, 256)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_DEFER_ACCEPT, 1)
	})
	if cerr != nil {
		return cerr
	}
	return err
}
