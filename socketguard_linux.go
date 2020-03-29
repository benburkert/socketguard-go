// +build linux

package socketguard

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const optCryptoInfo = 1

var ulpName = []byte{'s', 'o', 'c', 'k', 'e', 't', 'g', 'u', 'a', 'r', 'd', 0}

func (c *Config) control(fd uintptr) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, fd, syscall.SOL_TCP,
		unix.TCP_ULP, uintptr(unsafe.Pointer(&ulpName[0])), uintptr(len(ulpName)), 0)
	if errno != 0 {
		return errno
	}

	info := cryptoInfo{
		version:       uint16(c.Version),
		staticPublic:  c.StaticPublic,
		staticPrivate: c.StaticPrivate,
		peerPublic:    c.PeerPublic,
		presharedKey:  c.PresharedKey,
	}

	_, _, errno = syscall.Syscall6(syscall.SYS_SETSOCKOPT, fd, c.OptName,
		optCryptoInfo, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

type cryptoInfo struct {
	version uint16

	staticPublic  [KeySize]byte
	staticPrivate [KeySize]byte
	peerPublic    [KeySize]byte
	presharedKey  [KeySize]byte
}
