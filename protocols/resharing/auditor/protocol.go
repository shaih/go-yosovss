package auditor

import "C"
import (
	"fmt"
	"github.com/shaih/go-yosovss/primitives/vss"

	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/pedersen"
)

// PartyDebugParams is used to have some control on the way the code of the party is executed
type PartyDebugParams struct {
	SkipWitness                 bool // generate an empty witness
	SkipRefreshing              bool // skip the refreshing part and return empty nextShares/nextCommitments
	SkipVerificationVerifyShare bool // skip verification of VSS shares in verification
	SkipDealingFutureBroadcast  bool // skip generating anything related to future broadcast when dealing
	// warning: may trigger other issues. If one party skip future broadcast in dealing committee
	// this flag must be set when calling ALL the other parties in the following committees
	// as otherwise dealers may be incorrectly disqualified
	// furthermore, no future broadcast should ever be needed or the code may panic
}

// StartCommitteeParty initiates the protocol for a party participating in a t-of-n Pedersen VSS protocol using
// the new protocol with auditors
// It does one full refresh and returns the next commitments and (if the party if a next-committee member) its new share
// (or nil otherwise)
func StartCommitteeParty(
	pub *PublicInput,
	prv *PrivateInput,
	dbg *PartyDebugParams,
) (
	nextShare *vss.Share,
	nextCommitments []pedersen.Commitment,
	err error,
) {
	// FIXME: everywhere the protocol may fail if some malicious messages are sent
	// instead the protocol should continue and treat the party as malicious
	// but for debugging it is so much simpler not to add this, so we did not yet
	// However, a real implementation must add all these tests and handle things properly

	err = checkInputs(pub, prv) // sanity checks, T<=N, len(pub)=N+1,...
	if err != nil {
		return nil, nil, err
	}

	// Compute the indices of this party in the various initial committees (holding, verfication, ...)
	// indices.XYZ == -1 means that this party is not a part of the XYZ committee
	indices := pub.Committees.Indices(prv.ID)

	// Dealing
	// =======

	// If this party is part of the holding committee (i.e., holds a share),
	// then it plays the role of a dealer for its share in the 2-level
	// sharing and sends  shares to the verification committee.
	if indices.Hold >= 0 {
		msg, err := PerformDealing(pub, prv, dbg) // compute msg to be bcast by dealer
		if err != nil {
			return nil, nil, fmt.Errorf("party %d failed to perform dealing: %w", prv.ID, err)
		}
		prv.BC.Send(msgpack.Encode(msg)) // breoadcast this msg
	} else { // Do nothing if not part of the holding committee
		prv.BC.Send([]byte{}) // an empty message
	}

	// Receive the broadcast messages from all the dealers, returns an array of messages
	dealingMessages, err := ReceiveDealingMessages(prv.BC, pub.Committees.Hold)
	if err != nil {
		return nil, nil, fmt.Errorf("party %d failed receiving dealing messages: %w", prv.ID, err)
	}

	// Verification
	// ============

	// If this party is a member of the verification committee then verify all
	// the messages that were broadcast by dealer from the holding committe.
	if indices.Ver >= 0 {
		// For each dealer, either forward its shares to the next holding
		// committee or broadcast a complaint about it.
		msg, err := PerformVerification(pub, prv, indices.Ver, dealingMessages, dbg)
		if err != nil {
			return nil, nil, fmt.Errorf("party %d failed to perform verification: %w", prv.ID, err)
		}
		prv.BC.Send(msgpack.Encode(msg)) // broadcast the message
	} else { // Do nothing if not part of the verification committee
		prv.BC.Send([]byte{}) // an empty message
	}

	// Receive broadcast messages from the verification committee
	verificationMessages, err := ReceiveVerificationMessages(prv.BC, pub.Committees.Ver)
	if err != nil {
		return nil, nil, fmt.Errorf("party %d failed receiving verification messages: %w", prv.ID, err)
	}

	// Resolution (= Future Broadcast)
	// ===============================

	// If this party is a member of the resolution (future broadcast) committee,
	// then for every complaint (j complain about i) it publishes everything
	// that the dealer i sent to verifier j
	if indices.Res >= 0 {
		msg, err := PerformResolution(pub, prv, indices.Res, dealingMessages, verificationMessages)
		if err != nil {
			return nil, nil, fmt.Errorf("party %d failed to perform resolution: %w", prv.ID, err)
		}
		prv.BC.Send(msgpack.Encode(msg))
	} else { // Do nothing if not part of the resolution committee
		prv.BC.Send([]byte{})
	}

	// Receive broadcast messages from the resolution committee
	resolutionMessages, err := ReceiveResolutionMessages(prv.BC, pub.Committees.Res)
	if err != nil {
		return nil, nil, fmt.Errorf("party %d failed receiving resolution messages: %w", prv.ID, err)
	}

	// Refreshing
	// =========

	// Last phase where everybody computes the commitments of the refreshed shares
	// and parties in the new holding committee compute their refreshed shares

	if !dbg.SkipRefreshing {
		nextCommitments, nextShare, err = PerformRefresh(
			pub,
			prv,
			dealingMessages,
			verificationMessages,
			resolutionMessages,
			indices.Next,
			dbg,
		)
		if err != nil {
			return nil, nil, err
		}
	}

	return nextShare, nextCommitments, nil
}
