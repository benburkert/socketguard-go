package socketguard

import (
	"context"
	"io"
	"net"
	"syscall"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const KeySize = chacha20poly1305.KeySize

type Config struct {
	Version uint

	StaticPublic  [KeySize]byte
	StaticPrivate [KeySize]byte

	PeerPublic [KeySize]byte

	PresharedKey [KeySize]byte

	OptName uintptr
}

func (c *Config) Control(network, adress string, conn syscall.RawConn) error {
	var err error
	conn.Control(func(fd uintptr) {
		err = c.control(fd)
	})
	return err
}

func (c *Config) Dialer() *net.Dialer {
	return &net.Dialer{
		Control: c.Control,
	}
}

func (c *Config) Listener(ln net.Listener) error {
	sc, ok := ln.(syscall.Conn)
	if !ok {
		return net.UnknownNetworkError(ln.Addr().Network())
	}

	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}

	return c.Control(ln.Addr().Network(), ln.Addr().String(), rc)
}

func Dial(ctx context.Context, network, addr string, config *Config) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return config.Dialer().DialContext(ctx, network, addr)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

func GenerateKey(random io.Reader) (priv, pub [KeySize]byte, err error) {
	if _, err = io.ReadFull(random, priv[:]); err != nil {
		return priv, pub, err
	}

	// curve25519 clamp
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	return priv, pub, nil
}

func Listen(ctx context.Context, network, addr string, config *Config) (net.Listener, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		ln, err := new(net.ListenConfig).Listen(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		return ln, config.Listener(ln)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}
