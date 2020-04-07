package socketguard

import (
	"context"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/benburkert/socketguard-go/noise"
)

const (
	Construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	Identifier   = "SocketGuard v1"

	DefaultRekeyAfter  = 120 * time.Second
	DefaultRejectAfter = 180 * time.Second
)

var DefaultVersion = noise.NewVersion(0, 0)

type Config struct {
	Version noise.Version

	StaticPublic  noise.Key
	StaticPrivate noise.Key

	PeerPublic noise.Key

	PresharedKey noise.Key

	RekeyAfter  time.Duration
	RejectAfter time.Duration

	Rand io.Reader

	OptName uintptr

	PreferGo bool
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

func (c *Config) Listener(ln net.Listener) (net.Listener, error) {
	if c.PreferGo {
		return &listener{
			Listener: ln,

			config: *c,
		}, nil
	}

	sc, ok := ln.(syscall.Conn)
	if !ok {
		return nil, net.UnknownNetworkError(ln.Addr().Network())
	}

	rc, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}

	return ln, c.Control(ln.Addr().Network(), ln.Addr().String(), rc)
}

func Dial(ctx context.Context, network, addr string, config *Config) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		if config.PreferGo {
			netConn, err := new(net.Dialer).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			conn := Client(netConn, config)
			return conn, conn.sendHandshakeInitiation()
		}
		return config.Dialer().DialContext(ctx, network, addr)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

func Listen(ctx context.Context, network, addr string, config *Config) (net.Listener, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		ln, err := new(net.ListenConfig).Listen(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		return config.Listener(ln)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

type listener struct {
	net.Listener

	config Config
}

func (l *listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(conn, &l.config), nil
}
