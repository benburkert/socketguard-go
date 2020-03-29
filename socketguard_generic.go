// +build !linux

package socketguard

import "errors"

func (c *Config) control(fd uintptr) error {
	return errors.New("socketguard: unsupported platform")
}
