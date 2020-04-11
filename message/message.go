package message

import (
	"encoding/binary"

	"github.com/benburkert/socketguard-go/noise"
)

type Type uint32

const (
	invalid             Type = 0
	handshakeInitiation Type = 1
	handshakeResponse   Type = 2
	handshakeRekey      Type = 3
	data                Type = 4
)

var le = binary.LittleEndian

type header struct {
	Type
	Len uint32
}

func (h *header) pack(b []byte) []byte {
	var buf [8]byte
	le.PutUint32(buf[:], uint32(h.Type))
	le.PutUint32(buf[4:], uint32(h.Len))
	return append(b, buf[:]...)
}

func (h *header) unpack(b []byte) {
	h.Type = Type(le.Uint32(b))
	h.Len = le.Uint32(b[4:])
}

type Message interface {
	Type() Type
	Len() uint32

	pack([]byte) []byte
	unpack([]byte)
}

type HandshakeInitiation struct {
	UnencryptedEphemeral noise.Key
	EncryptedVersion     noise.EncryptedVersion
	EncryptedStatic      noise.EncryptedKey
	EncryptedCookie      noise.EncryptedCookie
}

func (h *HandshakeInitiation) Type() Type { return handshakeInitiation }

func (h *HandshakeInitiation) Len() uint32 {
	return noise.KeySize + noise.EncryptedKeySize +
		noise.EncryptedVersionSize + noise.EncryptedCookieSize
}

func (h *HandshakeInitiation) pack(b []byte) []byte {
	b = append(b, h.UnencryptedEphemeral[:]...)
	b = append(b, h.EncryptedVersion[:]...)
	b = append(b, h.EncryptedStatic[:]...)
	b = append(b, h.EncryptedCookie[:]...)
	return b
}

func (h *HandshakeInitiation) unpack(b []byte) {
	const (
		versionOffset = noise.KeySize
		staticOffset  = versionOffset + noise.EncryptedVersionSize
		cookieOffset  = staticOffset + noise.EncryptedKeySize
	)

	copy(h.UnencryptedEphemeral[:], b)
	copy(h.EncryptedVersion[:], b[versionOffset:])
	copy(h.EncryptedStatic[:], b[staticOffset:])
	copy(h.EncryptedCookie[:], b[cookieOffset:])
}

type HandshakeResponse struct {
	UnencryptedEphemeral noise.Key
	EncryptedVersion     noise.EncryptedVersion
	EncryptedCookie      noise.EncryptedCookie
}

func (h *HandshakeResponse) Type() Type { return handshakeResponse }

func (h *HandshakeResponse) Len() uint32 {
	return noise.KeySize + noise.EncryptedVersionSize +
		noise.EncryptedCookieSize
}

func (h *HandshakeResponse) pack(b []byte) []byte {
	b = append(b, h.UnencryptedEphemeral[:]...)
	b = append(b, h.EncryptedVersion[:]...)
	b = append(b, h.EncryptedCookie[:]...)
	return b
}

func (h *HandshakeResponse) unpack(b []byte) {
	const (
		versionOffset = noise.KeySize
		cookieOffset  = versionOffset + noise.EncryptedVersionSize
	)

	copy(h.UnencryptedEphemeral[:], b)
	copy(h.EncryptedVersion[:], b[versionOffset:])
	copy(h.EncryptedCookie[:], b[cookieOffset:])
}

type HandshakeRekey struct {
	UnencryptedEphemeral noise.Key
	EncryptedTimestamp   noise.EncryptedTimestamp
}

func (h *HandshakeRekey) Type() Type { return handshakeRekey }

func (h *HandshakeRekey) Len() uint32 {
	return noise.KeySize + noise.EncryptedTimestampSize
}

func (h *HandshakeRekey) pack(b []byte) []byte {
	b = append(b, h.UnencryptedEphemeral[:]...)
	b = append(b, h.EncryptedTimestamp[:]...)
	return b
}

func (h *HandshakeRekey) unpack(b []byte) {
	const timestampOffset = noise.KeySize

	copy(h.UnencryptedEphemeral[:], b)
	copy(h.EncryptedTimestamp[:], b[timestampOffset:])
}

type Data struct {
	EncryptedData []byte
}

func (d *Data) Type() Type { return data }

func (d *Data) Len() uint32 {
	return uint32(len(d.EncryptedData))
}

func (d *Data) pack(b []byte) []byte {
	return append(b, d.EncryptedData...)
}

func (d *Data) unpack(b []byte) {
	d.EncryptedData = make([]byte, len(b))
	copy(d.EncryptedData, b)
}
