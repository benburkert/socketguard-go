package socketguard

import (
	"crypto/rand"
	"io"
	"net"
	"time"

	"github.com/benburkert/socketguard-go/message"
	"github.com/benburkert/socketguard-go/noise"
)

type Conn struct {
	net.Conn

	initiator bool

	version       noise.Version
	staticPublic  noise.Key
	staticPrivate noise.Key
	peerPublic    noise.Key
	presharedKey  noise.Key

	rekeyAfter, rejectAfter time.Duration

	enc  *message.Encoder
	dec  *message.Decoder
	rbuf []byte

	hs handshake

	sending   *noise.SymmetricKey
	receiving *noise.SymmetricKey
}

func Client(conn net.Conn, config *Config) *Conn {
	return newConn(conn, config, true)
}

func Server(conn net.Conn, config *Config) *Conn {
	return newConn(conn, config, false)
}

func newConn(conn net.Conn, config *Config, initiator bool) *Conn {
	var (
		rekeyAfter, rejectAfter time.Duration
		randReader              io.Reader
	)

	if rekeyAfter = config.RekeyAfter; rekeyAfter == 0 {
		rekeyAfter = DefaultRekeyAfter
	}
	if rejectAfter = config.RejectAfter; rejectAfter == 0 {
		rejectAfter = DefaultRejectAfter
	}
	if randReader = config.Rand; randReader == nil {
		randReader = rand.Reader
	}

	return &Conn{
		Conn:      conn,
		initiator: initiator,

		version:       config.Version,
		staticPublic:  config.StaticPublic,
		staticPrivate: config.StaticPrivate,
		peerPublic:    config.PeerPublic,
		presharedKey:  config.PresharedKey,

		rekeyAfter:  rekeyAfter,
		rejectAfter: rejectAfter,

		enc: message.NewEncoder(conn),
		dec: message.NewDecoder(conn),

		hs: handshake{
			rand: randReader,
		},
	}
}

func (c *Conn) Handshake() error {
	if c.hs.state == handshakeFinished {
		return nil
	}

	if c.initiator {
		if c.hs.state == handshakeZeroed {
			if err := c.sendHandshakeInitiation(); err != nil {
				return err
			}
		}
		return c.recvHandshakeResponse()
	}

	if c.hs.state == handshakeZeroed {
		if err := c.recvHandshakeInitiation(); err != nil {
			return err
		}
	}
	return c.sendHandshakeResponse()
}

func (c *Conn) Read(b []byte) (int, error) {
	if len(c.rbuf) > 0 {
		return c.read(b, c.rbuf)
	}

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	for {
		msg, err := c.dec.Decode()
		if err != nil {
			return 0, err
		}

		switch msg := msg.(type) {
		case *message.Data:
			if c.receiving.Expired(c.rejectAfter) {
				return 0, ErrKeyExpired
			}

			buf, err := c.receiving.Open(nil, msg.EncryptedData)
			if err != nil {
				return 0, err
			}
			return c.read(b, buf)
		case *message.HandshakeRekey:
			err := c.hs.consumeRekey(msg, c.staticPrivate, c.staticPublic)
			if err != nil {
				return 0, err
			}

			recvKey, _ := c.hs.beginSession()
			c.receiving = noise.NewSymmetricKey(recvKey)
		}
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if c.sending.Expired(c.rekeyAfter) {
		if err := c.sendHandshakeRekey(); err != nil {
			return 0, err
		}
	}

	msg := &message.Data{
		EncryptedData: c.sending.Seal(nil, b),
	}

	if err := c.enc.Encode(msg); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *Conn) read(b, buf []byte) (int, error) {
	n := copy(b, buf)
	if n < len(buf) {
		c.rbuf = buf[n:]
	}
	return n, nil
}

func (c *Conn) recvHandshakeInitiation() error {
	msg, err := c.dec.Decode()
	if err != nil {
		return err
	}

	hi, ok := msg.(*message.HandshakeInitiation)
	if !ok {
		return UnexpectedMessageError(msg.Type())
	}

	c.peerPublic, err = c.hs.consumeInitiation(hi, c.staticPrivate,
		c.staticPublic)

	return err
}

func (c *Conn) recvHandshakeResponse() error {
	msg, err := c.dec.Decode()
	if err != nil {
		return err
	}

	hr, ok := msg.(*message.HandshakeResponse)
	if !ok {
		return UnexpectedMessageError(msg.Type())
	}

	if err := c.hs.consumeResponse(hr, c.staticPrivate, c.presharedKey); err != nil {
		return err
	}

	sendKey, recvKey := c.hs.beginSession()
	c.sending = noise.NewSymmetricKey(sendKey)
	c.receiving = noise.NewSymmetricKey(recvKey)

	return nil
}

func (c *Conn) sendHandshakeInitiation() error {
	hi, err := c.hs.createInitiation(c.staticPrivate, c.staticPublic,
		c.peerPublic, c.version)
	if err != nil {
		return err
	}

	return c.enc.Encode(hi)
}

func (c *Conn) sendHandshakeRekey() error {
	hr, err := c.hs.createRekey(c.peerPublic)
	if err != nil {
		return err
	}

	if err := c.enc.Encode(hr); err != nil {
		return err
	}

	sendKey, _ := c.hs.beginSession()
	c.sending = noise.NewSymmetricKey(sendKey)
	return nil
}

func (c *Conn) sendHandshakeResponse() error {
	hr, err := c.hs.createResponse(c.staticPrivate, c.staticPublic,
		c.peerPublic, c.presharedKey)
	if err != nil {
		return err
	}

	if err = c.enc.Encode(hr); err != nil {
		return err
	}

	recvKey, sendKey := c.hs.beginSession()
	c.receiving = noise.NewSymmetricKey(recvKey)
	c.sending = noise.NewSymmetricKey(sendKey)

	return nil
}
