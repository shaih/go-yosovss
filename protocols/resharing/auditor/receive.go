package auditor

// This file is a template generating gen-matrix_generic.go

import (
	"fmt"
	"github.com/cheekybits/genny/generic"
	"github.com/shaih/go-yosovss/communication"
	"github.com/shaih/go-yosovss/msgpack"
)

//go:generate genny -in=$GOFILE -out=gen-$GOFILE gen "MessageType=DealingMessage,VerificationMessage,WitnessMessage,AuditingMessage,ResolutionMessage"

type MessageType generic.Type

// ReceiveMessageTypes receives and parse the messages sent by dealers in the dealing round
// parties is the list of parties in the round
func ReceiveMessageTypes(bc communication.BroadcastChannel, parties []int) ([]MessageType, error) {
	messages := make([]MessageType, len(parties))

	_, bm := bc.ReceiveRound()

	for i, party := range parties {
		err := msgpack.Decode(bm[party].Payload, &messages[i])
		if err != nil {
			return nil, fmt.Errorf("decoding message from party %d (id=%d) failed: %v", i, party, err)
		}
	}

	return messages, nil
}
