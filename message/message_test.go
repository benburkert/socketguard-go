package message

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/benburkert/socketguard-go/internal/must"
	"github.com/benburkert/socketguard-go/noise"
)

var (
	sPriv, sPub   = must.GenerateKeyPair()
	ePriv, ePub   = must.GenerateKeyPair()
	rsPriv, rsPub = must.GenerateKeyPair()
	rePriv, rePub = must.GenerateKeyPair()

	kEnc = must.GenerateKey()

	v, rv       = noise.NewVersion(1, 0), noise.NewVersion(0, 100)
	vEnc, rvEnc = must.EncryptVersion(v, kEnc), must.EncryptVersion(rv, kEnc)

	sEnc  = must.EncryptKey(sPub, kEnc)
	rsEnc = must.EncryptKey(rsPub, kEnc)

	t    = noise.GenerateTimestamp()
	tEnc = must.EncryptTimestamp(t, kEnc)

	dEnc = must.RandBytes(1024 + noise.AuthTagSize)
)

func TestHandshakeInitiation(t *testing.T) {
	testCases{
		{
			name: "zero-value",

			buf: must.Bytes(
				uint32(handshakeInitiation),
				must.Bytes(must.LenU32,
					make([]byte, noise.KeySize),
					make([]byte, noise.EncryptedVersionSize),
					make([]byte, noise.EncryptedKeySize),
				),
			),

			msg: &HandshakeInitiation{},
		},
		{
			name: "happy-path",

			buf: must.Bytes(
				uint32(handshakeInitiation),
				must.Bytes(must.LenU32,
					ePub[:],
					vEnc[:],
					sEnc[:],
				),
			),

			msg: &HandshakeInitiation{
				UnencryptedEphemeral: ePub,
				EncryptedVersion:     vEnc,
				EncryptedStatic:      sEnc,
			},
		},
	}.test(t)
}

func TestHandshakeResponse(t *testing.T) {
	testCases{
		{
			name: "zero-value",

			buf: must.Bytes(
				uint32(handshakeResponse),
				must.Bytes(must.LenU32,
					make([]byte, noise.KeySize),
					make([]byte, noise.EncryptedVersionSize),
				),
			),

			msg: &HandshakeResponse{},
		},
		{
			name: "happy-path",

			buf: must.Bytes(
				uint32(handshakeResponse),
				must.Bytes(must.LenU32,
					rePub[:],
					rvEnc[:],
				),
			),

			msg: &HandshakeResponse{
				UnencryptedEphemeral: rePub,
				EncryptedVersion:     rvEnc,
			},
		},
	}.test(t)
}

func TestHandshakeRekey(t *testing.T) {
	testCases{
		{
			name: "zero-value",

			buf: must.Bytes(
				uint32(handshakeRekey),
				must.Bytes(must.LenU32,
					make([]byte, noise.KeySize),
					make([]byte, noise.EncryptedTimestampSize),
				),
			),

			msg: &HandshakeRekey{},
		},
		{
			name: "happy-path",

			buf: must.Bytes(
				uint32(handshakeRekey),
				must.Bytes(must.LenU32,
					rePub[:],
					tEnc[:],
				),
			),

			msg: &HandshakeRekey{
				UnencryptedEphemeral: rePub,
				EncryptedTimestamp:   tEnc,
			},
		},
	}.test(t)
}

func TestData(t *testing.T) {
	testCases{
		{
			name: "happy-path",

			buf: must.Bytes(
				uint32(data),
				must.Bytes(must.LenU32,
					dEnc,
				),
			),

			msg: &Data{
				EncryptedData: dEnc,
			},
		},
	}.test(t)
}

type testCase struct {
	name string

	buf []byte

	msg Message
	err error
}

func (test testCase) test(t *testing.T) {
	t.Helper()

	t.Run(test.name, func(t *testing.T) {
		t.Parallel()

		msg, err := NewDecoder(bytes.NewBuffer(test.buf)).Decode()
		if err != nil {
			t.Fatal(err)
		}

		if want, got := test.msg, msg; !reflect.DeepEqual(want, got) {
			t.Errorf("want msg %x, got %x", want, got)
		}

		var buf bytes.Buffer
		if err := NewEncoder(&buf).Encode(msg); err != nil {
			t.Fatal(err)
		}
		if want, got := test.buf, buf.Bytes(); !bytes.Equal(want, got) {
			t.Errorf("want %#v written bytes, got %#v", want, got)
		}
	})
}

type testCases []testCase

func (tests testCases) test(t *testing.T) {
	t.Helper()

	for _, test := range tests {
		test.test(t)
	}
}
