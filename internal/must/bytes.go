package must

import (
	"encoding/binary"
	"fmt"
)

var le = binary.LittleEndian

type Prefix int

const (
	LenU16 Prefix = iota
	LenU32
	LenU64
)

func Bytes(xs ...interface{}) []byte {
	var buf []byte
	for i, x := range xs {
		switch x := x.(type) {
		case Prefix:
			switch x {
			case LenU16, LenU32, LenU64:
				return append(buf, LengthPrefixBytes(x, xs[i+1:]...)...)
			default:
				panic(fmt.Sprintf("unknown prefix: %d", x))
			}
		case []byte:
			buf = append(buf, x...)
		case byte:
			buf = append(buf, x)
		case string:
			buf = append(buf, []byte(x)...)
		case uint16:
			tmp := [2]byte{}
			le.PutUint16(tmp[:], x)
			buf = append(buf, tmp[:]...)
		case uint32:
			tmp := [4]byte{}
			le.PutUint32(tmp[:], x)
			buf = append(buf, tmp[:]...)
		case uint64:
			tmp := [8]byte{}
			le.PutUint64(tmp[:], x)
			buf = append(buf, tmp[:]...)
		default:
			panic(fmt.Sprintf("unsupported type: %T", x))
		}
	}
	return buf
}

func LengthPrefixBytes(pfx Prefix, xs ...interface{}) []byte {
	buf := Bytes(xs...)
	switch pfx {
	case LenU16:
		buf = append(make([]byte, 2), buf...)
		le.PutUint16(buf[:2], uint16(len(buf[2:])))
	case LenU32:
		buf = append(make([]byte, 4), buf...)
		le.PutUint32(buf[:4], uint32(len(buf[4:])))
	case LenU64:
		buf = append(make([]byte, 8), buf...)
		le.PutUint64(buf[:8], uint64(len(buf[8:])))
	default:
		panic("unknown length prefix")
	}
	return buf
}
