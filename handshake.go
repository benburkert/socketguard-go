package socketguard

import (
	"io"

	"github.com/benburkert/socketguard-go/message"
	"github.com/benburkert/socketguard-go/noise"
)

var (
	initHash        noise.HashSum
	initChainingKey noise.HashSum
)

func init() {
	initChainingKey = noise.GenerateHashSum([]byte(Construction))
	initHash = initChainingKey.Hash([]byte(Identifier))
}

type handshakeState int

const (
	handshakeZeroed handshakeState = iota
	handshakeInitiated
	handshakeFinished
)

type handshake struct {
	rand io.Reader

	state handshakeState

	version          noise.Version
	ephemeralPrivate noise.Key
	remoteEphemeral  noise.Key
	remoteTimestamp  noise.Timestamp
	staticStatic     noise.Key

	chainingKey noise.HashSum
	hash        noise.HashSum

	sendRekey noise.HashSum
	recvRekey noise.HashSum
}

func (h *handshake) createInitiation(sPriv, sPub, rs noise.Key, version noise.Version) (*message.HandshakeInitiation, error) {
	var (
		msg message.HandshakeInitiation

		chainingKey noise.HashSum
		hash        noise.HashSum
		key         noise.Key
	)

	chainingKey = initChainingKey
	hash = initHash.Hash(rs[:])

	/* e */
	ePriv, ePub, err := noise.GenerateKeyPair(h.rand)
	if err != nil {
		return nil, err
	}
	msg.UnencryptedEphemeral = ePub
	hash.Mix(ePub[:])
	chainingKey.MixKDF1(ePub[:])

	/* es */
	key = chainingKey.MixDH(ePriv, rs)

	/* version */
	msg.EncryptedVersion = hash.MixSealVersion(key, version)
	key = chainingKey.MixVersion(version)

	/* s */
	msg.EncryptedStatic = hash.MixSealKey(key, sPub)

	/* ss */
	ss := sPriv.SharedSecret(rs)
	key = chainingKey.MixKey(ss)

	h.chainingKey = chainingKey
	h.hash = hash
	h.ephemeralPrivate = ePriv
	h.staticStatic = ss
	h.state = handshakeInitiated

	return &msg, nil
}

func (h *handshake) consumeInitiation(msg *message.HandshakeInitiation, sPriv, sPub noise.Key) (noise.Key, error) {
	var (
		chainingKey noise.HashSum
		hash        noise.HashSum
		key         noise.Key
	)

	chainingKey = initChainingKey
	hash = initHash.Hash(sPub[:])

	/* e */

	e := msg.UnencryptedEphemeral
	hash.Mix(e[:])
	chainingKey.MixKDF1(e[:])

	/* es */
	key = chainingKey.MixDH(sPriv, e)

	/* version */
	v := hash.MixOpenVersion(key, msg.EncryptedVersion)
	key = chainingKey.MixVersion(v)

	/* s */
	s := hash.MixOpenKey(key, msg.EncryptedStatic)

	/* ss */
	ss := sPriv.SharedSecret(s)
	key = chainingKey.MixKey(ss)

	/* Success! Copy everything to handshake */
	h.remoteEphemeral = e
	h.staticStatic = ss
	h.version = v
	h.hash = hash
	h.chainingKey = chainingKey
	h.state = handshakeInitiated

	return s, nil
}

func (h *handshake) createResponse(sPriv, sPub, rs, psk noise.Key) (*message.HandshakeResponse, error) {
	var (
		msg message.HandshakeResponse

		tmpHash noise.HashSum
		key     noise.Key
	)

	/* e */
	ePriv, ePub, err := noise.GenerateKeyPair(h.rand)
	if err != nil {
		return nil, err
	}
	msg.UnencryptedEphemeral = ePub
	h.hash.Mix(ePub[:])
	h.chainingKey.MixKDF1(ePub[:])

	/* ee */

	h.chainingKey.MixDH(ePriv, h.remoteEphemeral)

	/* se */
	h.chainingKey.MixDH(ePriv, rs)

	/* version */
	msg.EncryptedVersion = h.hash.MixSealVersion(key, h.version)

	/* psk */
	tmpHash, key = h.chainingKey.MixPSK(psk)
	h.hash.Mix(tmpHash[:])

	h.sendRekey = h.chainingKey
	h.recvRekey = h.chainingKey
	h.state = handshakeFinished
	return &msg, nil
}

func (h *handshake) consumeResponse(msg *message.HandshakeResponse, sPriv, psk noise.Key) error {
	var (
		hash noise.HashSum
		key  noise.Key
	)

	/* e */
	e := msg.UnencryptedEphemeral
	h.hash.Mix(e[:])
	h.chainingKey.MixKDF1(e[:])

	/* ee */
	h.chainingKey.MixDH(h.ephemeralPrivate, e)

	/* se */
	h.chainingKey.MixDH(sPriv, e)

	/* version */
	h.version = h.hash.MixOpenVersion(key, msg.EncryptedVersion)

	/* psk */
	hash, key = h.chainingKey.MixPSK(psk)
	h.hash.Mix(hash[:])

	h.sendRekey = h.chainingKey
	h.recvRekey = h.chainingKey
	h.state = handshakeFinished
	return nil
}

func (h *handshake) createRekey(rs noise.Key) (*message.HandshakeRekey, error) {
	var (
		msg message.HandshakeRekey

		chainingKey noise.HashSum
		hash        noise.HashSum
		key         noise.Key
	)

	chainingKey = h.sendRekey
	hash = initHash.Hash(rs[:])

	/* e */
	ePriv, ePub, err := noise.GenerateKeyPair(h.rand)
	if err != nil {
		return nil, err
	}
	msg.UnencryptedEphemeral = ePub
	hash.Mix(ePub[:])
	chainingKey.MixKDF1(ePub[:])

	/* es */
	chainingKey.MixDH(ePriv, rs)

	/* ss */
	chainingKey.MixKey(h.staticStatic)

	/* {t} */
	ts := noise.GenerateTimestamp()
	msg.EncryptedTimestamp = hash.MixSealTimetstamp(key, ts)

	/* Success! */
	h.chainingKey = chainingKey
	h.sendRekey = chainingKey
	return &msg, nil
}

func (h *handshake) consumeRekey(msg *message.HandshakeRekey, sPriv, sPub noise.Key) error {
	var (
		chainingKey noise.HashSum
		hash        noise.HashSum
		key         noise.Key
	)

	chainingKey = h.recvRekey
	hash = initHash.Hash(sPub[:])

	/* e */
	e := msg.UnencryptedEphemeral
	hash.Mix(e[:])
	chainingKey.MixKDF1(e[:])

	/* es */
	chainingKey.MixDH(sPriv, e)

	/* ss */
	chainingKey.MixKey(h.staticStatic)

	/* {t} */
	ts := hash.MixOpenTimestamp(key, msg.EncryptedTimestamp)
	if !ts.After(h.remoteTimestamp) {
		return ErrRekeyFailed
	}

	/* Success! */
	h.remoteTimestamp = ts
	h.hash = hash
	h.chainingKey = chainingKey
	h.recvRekey = chainingKey

	return nil
}

func (h *handshake) beginSession() (noise.Key, noise.Key) {
	sum1, sum2 := noise.KDF2(h.chainingKey, nil)
	return noise.Key(sum1), noise.Key(sum2)
}
