package message

import "io"

type Encoder struct {
	w io.Writer
}

func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w}
}

func (e *Encoder) Encode(msg Message) error {
	hdr := &header{
		Type: msg.Type(),
		Len:  msg.Len(),
	}

	buf := make([]byte, 0, 8+msg.Len())
	buf = hdr.pack(buf)
	buf = msg.pack(buf)

	_, err := e.w.Write(buf)
	return err
}
