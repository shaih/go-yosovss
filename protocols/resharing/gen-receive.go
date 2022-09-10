// This file was automatically generated by genny.
// Any changes will be lost if this file is regenerated.
// see https://github.com/cheekybits/genny

package resharing

import (
	"fmt"

	"github.com/shaih/go-yosovss/communication"
	"github.com/shaih/go-yosovss/msgpack"
)

// This file (receive.go) is a template generating gen-receive.go

// ReceiveDealingMessages receives and parse the messages sent by dealers in the dealing round
// parties is the list of parties in the round
func ReceiveDealingMessages(bc communication.BroadcastChannel, parties []int) ([]DealingMessage, error) {
	messages := make([]DealingMessage, len(parties))

	_, bm := bc.ReceiveRound()

	for i, party := range parties {
		err := msgpack.Decode(bm[party].Payload, &messages[i])
		if err != nil {
			return nil, fmt.Errorf("decoding message from party %d (id=%d) failed: %v", i, party, err)
		}
	}

	return messages, nil
}

// This file (receive.go) is a template generating gen-receive.go

// ReceiveVerificationMessages receives and parse the messages sent by dealers in the dealing round
// parties is the list of parties in the round
func ReceiveVerificationMessages(bc communication.BroadcastChannel, parties []int) ([]VerificationMessage, error) {
	messages := make([]VerificationMessage, len(parties))

	_, bm := bc.ReceiveRound()

	for i, party := range parties {
		err := msgpack.Decode(bm[party].Payload, &messages[i])
		if err != nil {
			return nil, fmt.Errorf("decoding message from party %d (id=%d) failed: %v", i, party, err)
		}
	}

	return messages, nil
}

// This file (receive.go) is a template generating gen-receive.go

// ReceiveResolutionMessages receives and parse the messages sent by dealers in the dealing round
// parties is the list of parties in the round
func ReceiveResolutionMessages(bc communication.BroadcastChannel, parties []int) ([]ResolutionMessage, error) {
	messages := make([]ResolutionMessage, len(parties))

	_, bm := bc.ReceiveRound()

	for i, party := range parties {
		err := msgpack.Decode(bm[party].Payload, &messages[i])
		if err != nil {
			return nil, fmt.Errorf("decoding message from party %d (id=%d) failed: %v", i, party, err)
		}
	}

	return messages, nil
}