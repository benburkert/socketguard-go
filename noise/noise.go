package noise

import (
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"io"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/poly1305"
)

var le = binary.LittleEndian

const (
	AuthTagSize   = poly1305.TagSize
	CookieSize    = 16
	HashSumSize   = blake2s.Size
	KeySize       = chacha20poly1305.KeySize
	TimestampSize = 8
	VersionSize   = 8

	EncryptedCookieSize    = CookieSize + AuthTagSize
	EncryptedKeySize       = KeySize + AuthTagSize
	EncryptedTimestampSize = TimestampSize + AuthTagSize
	EncryptedVersionSize   = VersionSize + AuthTagSize
)

type (
	AuthTag   [AuthTagSize]byte
	Cookie    [CookieSize]byte
	Key       [KeySize]byte
	Timestamp [TimestampSize]byte
	HashSum   [HashSumSize]byte
	Version   [VersionSize]byte

	EncryptedCookie    [EncryptedCookieSize]byte
	EncryptedKey       [EncryptedKeySize]byte
	EncryptedTimestamp [EncryptedTimestampSize]byte
	EncryptedVersion   [EncryptedVersionSize]byte
)

func init() {
	if chacha20poly1305.KeySize != curve25519.ScalarSize {
		panic("impossible")
	}
}

func GenerateCookie(random io.Reader) (Cookie, error) {
	var cookie Cookie
	return cookie, getRandom(cookie[:], random)
}

func GenerateKey(random io.Reader) (Key, error) {
	var key Key
	return key, getRandom(key[:], random)
}

func GenerateKeyPair(random io.Reader) (priv, pub Key, err error) {
	if err = getRandom(priv[:], random); err != nil {
		return priv, pub, err
	}

	// curve25519 clamp
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	kp := struct{ priv, pub *Key }{&priv, &pub}
	curve25519.ScalarBaseMult((*[32]byte)(kp.pub), (*[32]byte)(kp.priv))

	return priv, pub, nil
}

func (k Key) AEAD() cipher.AEAD {
	aead, err := chacha20poly1305.New(k[:])
	if err != nil {
		panic("impossible")
	}
	return aead
}

func (k Key) SharedSecret(pub Key) Key {
	var dst Key
	curve25519.ScalarMult((*[32]byte)(&dst), (*[32]byte)(&k), (*[32]byte)(&pub))
	return dst
}

var epoch = time.Now()

func GenerateTimestamp() Timestamp {
	var t Timestamp

	le.PutUint64(t[:], uint64(time.Since(epoch).Round(time.Millisecond)))

	return t
}

func (t Timestamp) After(t2 Timestamp) bool {
	return le.Uint64(t[:]) > le.Uint64(t2[:])
}

func (t Timestamp) Expired(period time.Duration) bool {
	now := GenerateTimestamp()
	return le.Uint64(now[:])-le.Uint64(t[:]) > uint64(period)
}

func getRandom(dst []byte, random io.Reader) error {
	_, err := io.ReadFull(random, dst)
	return err
}

func GenerateHashSum(data []byte) HashSum {
	return HashSum(blake2s.Sum256(data))
}

func (h HashSum) Hash(data []byte) HashSum {
	var dst HashSum
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	return dst
}

func (h *HashSum) Mix(data []byte) {
	sum := h.Hash(data)
	copy(h[:], sum[:])
}

func (h *HashSum) MixCookie(cookie Cookie) Key {
	return Key(h.MixKDF2(cookie[:]))
}

func (h *HashSum) MixDH(priv, pub Key) Key {
	return h.MixKey(priv.SharedSecret(pub))
}

func (h *HashSum) MixKDF1(data []byte) {
	sum := KDF1(*h, data)
	copy(h[:], sum[:])
}

func (h *HashSum) MixKDF2(data []byte) HashSum {
	sum1, sum2 := KDF2(*h, data)
	copy(h[:], sum1[:])
	return sum2
}

func (h *HashSum) MixKDF3(data []byte) (HashSum, HashSum) {
	sum1, sum2, sum3 := KDF3(*h, data)
	copy(h[:], sum1[:])
	return sum2, sum3
}

func (h *HashSum) MixKey(key Key) Key {
	return Key(h.MixKDF2(key[:]))
}

func (h *HashSum) MixOpen(dst []byte, key Key, cipher []byte) {
	var zeroNonce [chacha20poly1305.NonceSize]byte

	key.AEAD().Open(dst[:0], zeroNonce[:], cipher, h[:])
	h.Mix(cipher)
}

func (h *HashSum) MixOpenCookie(key Key, encCookie EncryptedCookie) Cookie {
	var dst Cookie
	h.MixOpen(dst[:0], key, encCookie[:])
	return dst
}

func (h *HashSum) MixOpenKey(encKey Key, tgtKey EncryptedKey) Key {
	var dst Key
	h.MixOpen(dst[:0], encKey, tgtKey[:])
	return dst
}

func (h *HashSum) MixOpenTimestamp(key Key, encT EncryptedTimestamp) Timestamp {
	var dst Timestamp
	h.MixOpen(dst[:0], key, encT[:])
	return dst
}

func (h *HashSum) MixOpenVersion(key Key, encVersion EncryptedVersion) Version {
	var dst Version
	h.MixOpen(dst[:0], key, encVersion[:])
	return dst
}

func (h *HashSum) MixPSK(psk Key) (HashSum, Key) {
	sum, key := h.MixKDF3(psk[:])
	return sum, Key(key)
}

func (h *HashSum) MixSeal(dst []byte, key Key, plain []byte) {
	var zeroNonce [chacha20poly1305.NonceSize]byte

	key.AEAD().Seal(dst[:0], zeroNonce[:], plain, h[:])
	h.Mix(dst)
}

func (h *HashSum) MixSealCookie(key Key, cookie Cookie) EncryptedCookie {
	var dst EncryptedCookie
	h.MixSeal(dst[:], key, cookie[:])
	return dst
}

func (h *HashSum) MixSealKey(encKey, tgtKey Key) EncryptedKey {
	var dst EncryptedKey
	h.MixSeal(dst[:], encKey, tgtKey[:])
	return dst
}

func (h *HashSum) MixSealTimetstamp(key Key, ts Timestamp) EncryptedTimestamp {
	var dst EncryptedTimestamp
	h.MixSeal(dst[:], key, ts[:])
	return dst
}

func (h *HashSum) MixSealVersion(key Key, version Version) EncryptedVersion {
	var dst EncryptedVersion
	h.MixSeal(dst[:], key, version[:])
	return dst
}

func KDF1(key HashSum, data []byte) HashSum {
	return HMAC(HMAC(key, data), []byte{0x1})
}

func KDF2(key HashSum, data []byte) (sum1, sum2 HashSum) {
	sec := HMAC(key, data)
	sum1 = HMAC(sec, []byte{0x1})
	sum2 = HMAC(sec, sum1[:], []byte{0x2})
	return sum1, sum2
}

func KDF3(key HashSum, data []byte) (sum1, sum2, sum3 HashSum) {
	sec := HMAC(key, data)
	sum1 = HMAC(sec, []byte{0x1})
	sum2 = HMAC(sec, sum1[:], []byte{0x2})
	sum3 = HMAC(sec, sum2[:], []byte{0x3})
	return sum1, sum2, sum3
}

func HMAC(key HashSum, datas ...[]byte) HashSum {
	var dst HashSum
	mac := hmac.New(hmacHash, key[:])
	for _, data := range datas {
		mac.Write(data)
	}
	mac.Sum(dst[:0])
	return dst
}

func hmacHash() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

type SymmetricKey struct {
	Key
	Counter uint64
	Timestamp
}

func NewSymmetricKey(key Key) *SymmetricKey {
	return &SymmetricKey{
		Key:       key,
		Timestamp: GenerateTimestamp(),
	}
}

func (s *SymmetricKey) Open(dst, ciphertext []byte) ([]byte, error) {
	return s.AEAD().Open(dst[:0], s.nonce(), ciphertext, nil)
}

func (s *SymmetricKey) Seal(dst, plaintext []byte) []byte {
	return s.AEAD().Seal(dst[:0], s.nonce(), plaintext, nil)
}

func (s *SymmetricKey) nonce() []byte {
	defer func() { s.Counter++ }()

	var nonce [chacha20poly1305.NonceSize]byte

	le.PutUint64(nonce[len(nonce)-8:], s.Counter)
	return nonce[:]
}

func NewVersion(min, max uint16) Version {
	var v Version
	le.PutUint16(v[:], min)
	le.PutUint16(v[4:], max)
	return v
}

func (v Version) Min() uint16 {
	return le.Uint16(v[:])
}

func (v Version) Max() uint16 {
	return le.Uint16(v[4:])
}
