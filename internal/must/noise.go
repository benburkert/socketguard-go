package must

import (
	"crypto/rand"

	"github.com/benburkert/socketguard-go/noise"
	"golang.org/x/crypto/poly1305"
)

func EncryptKey(src, key noise.Key) noise.EncryptedKey {
	var dst noise.EncryptedKey
	xor(dst[:noise.KeySize], src[:], key[:])
	mac(dst[noise.KeySize:], dst[:noise.KeySize], key)
	return dst
}

func EncryptTimestamp(t noise.Timestamp, key noise.Key) noise.EncryptedTimestamp {
	var dst noise.EncryptedTimestamp
	xor(dst[:noise.TimestampSize], t[:], append(append([]byte{}, key[:]...), key[:]...)[:noise.TimestampSize])
	mac(dst[noise.TimestampSize:], dst[:noise.TimestampSize], key)
	return dst
}

func EncryptVersion(v noise.Version, key noise.Key) noise.EncryptedVersion {
	var dst noise.EncryptedVersion
	xor(dst[:noise.VersionSize], v[:], key[:noise.VersionSize])
	mac(dst[noise.VersionSize:], dst[:noise.TimestampSize], key)
	return dst
}

func GenerateKey() noise.Key {
	key, err := noise.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func GenerateKeyPair() (priv, pub noise.Key) {
	var err error
	if priv, pub, err = noise.GenerateKeyPair(rand.Reader); err != nil {
		panic(err)
	}
	return priv, pub
}

func xor(dst, src, mask []byte) {
	if len(dst) != len(src) || len(src) != len(mask) {
		panic("impossible")
	}

	for i := range dst {
		dst[i] = src[i] ^ mask[i]
	}
}

func mac(dst, src []byte, key noise.Key) {
	var tag [noise.AuthTagSize]byte
	poly1305.Sum(&tag, src[:], (*[noise.KeySize]byte)(&key))
	copy(dst[:], tag[:])
}
