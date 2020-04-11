package message

import (
	"fmt"
	"io"
)

type Decoder struct {
	r io.Reader
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r}
}

func (d *Decoder) Decode() (Message, error) {
	hdr, err := d.decodeHeader()
	if err != nil {
		return nil, err
	}

	var msg Message
	switch hdr.Type {
	case handshakeInitiation:
		msg = new(HandshakeInitiation)
	case handshakeResponse:
		msg = new(HandshakeResponse)
	case handshakeRekey:
		msg = new(HandshakeRekey)
	case data:
		msg = new(Data)
	default:
		return nil, UnknownTypeError(hdr.Type)
	}

	buf := make([]byte, hdr.Len)
	if _, err := io.ReadFull(d.r, buf); err != nil {
		return nil, err
	}
	if msg.Len() > 0 && msg.Len() > hdr.Len {
		buf = buf[:msg.Len()]
	}

	msg.unpack(buf)
	return msg, nil
}

func (d *Decoder) decodeHeader() (*header, error) {
	var buf [8]byte
	if _, err := io.ReadFull(d.r, buf[:]); err != nil {
		return nil, err
	}

	hdr := new(header)
	hdr.unpack(buf[:])

	return hdr, nil
}

type UnknownTypeError Type

func (e UnknownTypeError) Error() string {
	return fmt.Sprintf("socketguard: unknown error type: %d", e)
}
