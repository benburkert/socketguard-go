// +build !linux

package socketguard

import "syscall"

func (c *Config) control(fd uintptr) error {
	return syscall.ENOENT
}
