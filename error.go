package socketguard

import (
	"errors"
	"fmt"

	"github.com/benburkert/socketguard-go/message"
)

var (
	ErrKeyExpired  = errors.New("socketguard: receiving key expired")
	ErrRekeyFailed = errors.New("socketguard: rekey failed")
)

type UnexpectedMessageError message.Type

func (e UnexpectedMessageError) Error() string {
	return fmt.Sprintf("socketguard: unexpected message type: %d", e)
}
