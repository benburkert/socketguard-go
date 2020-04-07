// +build linux

package socketguard

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/benburkert/socketguard-go/noise"
)

const optCryptoInfo = 1

var ulpName = []byte{'s', 'o', 'c', 'k', 'e', 't', 'g', 'u', 'a', 'r', 'd', 0}

func (c *Config) control(fd uintptr) error {
	if c.OptName == 0 {
		return errors.New("socketguard: OptName config required")
	}

	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, fd, syscall.SOL_TCP,
		unix.TCP_ULP, uintptr(unsafe.Pointer(&ulpName[0])), uintptr(len(ulpName)), 0)
	if errno != 0 {
		return errno
	}

	info := cryptoInfo{
		minVersion:    c.Version.Min(),
		maxVersion:    c.Version.Max(),
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
	minVersion uint16
	maxVersion uint16

	staticPublic  [noise.KeySize]byte
	staticPrivate [noise.KeySize]byte
	peerPublic    [noise.KeySize]byte
	presharedKey  [noise.KeySize]byte
}
