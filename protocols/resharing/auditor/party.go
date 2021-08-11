package auditor

import "C"
import (
	"fmt"
	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/vss"
	log "github.com/sirupsen/logrus"
)

// WARNING TODO FIXME
// Work still in progress, mostly incorrect code (old code)

// StartCommitteeParty initiates the protocol for a party participating in a t-of-n Pedersen VSS protocol using
// the new protocol with auditors
// It does one full refresh and returns the next commitments and (if the party if a next-committee member) its new share
// (or nil otherwise)
func StartCommitteeParty(
	pub *PublicInput,
	prv *PrivateInput,
) (
	nextShare *vss.Share,
	nextCommitments []pedersen.Commitment,
	err error,
) {
	myLog := log.WithFields(log.Fields{
		"id": prv.Id,
		"n":  pub.N,
		"t":  pub.T,
	})

	err = checkInputs(pub, prv)
	if err != nil {
		return nil, nil, err
	}

	// Compute the indices of the party in the various initial committees (-1 if not a part of a committee)
	indices := pub.Committees.Indices(prv.Id)

	// Dealing
	// =======

	// Participate in the holding committee when a dealer
	// The holding committee performs the two level sharing and sends shares
	// to the verification committee.
	if indices.Hold >= 0 {
		msg, err := PerformDealing(pub, prv)
		if err != nil {
			return nil, nil, fmt.Errorf("party %d failed to perform dealing: %w", prv.Id, err)
		}
		prv.BC.Send(msgpack.Encode(msg))
	} else { // Do nothing if not part of the holding committee
		prv.BC.Send([]byte{})
	}

	// Receive dealing messages
	dealingMessages, err := ReceiveDealingMessages(prv.BC, pub.Committees.Hold)
	if err != nil {
		return nil, nil, fmt.Errorf("party %d failed receiving dealing messages: %w", prv.Id, err)
	}

	// Verification
	// ============

	if indices.Ver >= 0 {
		msg, err := PerformVerification(pub, prv, indices.Ver, dealingMessages)
		if err != nil {
			return nil, nil, fmt.Errorf("party %d failed to perform verification: %w", prv.Id, err)
		}
		prv.BC.Send(msgpack.Encode(msg))
	} else { // Do nothing if not part of the holding committee
		prv.BC.Send([]byte{})
	}

	// Receive verification messages
	verificationMessages, err := ReceiveVerificationMessages(prv.BC, pub.Committees.Ver)
	if err != nil {
		return nil, nil, fmt.Errorf("party %d failed receiving verification messages: %w", prv.Id, err)
	}

	// Resolution (= Future Broadcast)
	// ===============================

	// FIXME

	prv.BC.Send([]byte{})
	prv.BC.ReceiveRound()

	// Witness
	// =======

	// FIXME

	prv.BC.Send([]byte{})
	prv.BC.ReceiveRound()

	// Auditing
	// ========

	// FIXME

	prv.BC.Send([]byte{})
	prv.BC.ReceiveRound()

	// Refreshing
	// =========

	// Last phase where everybody computes the commitments of the refreshed shares
	// and parties in the new holding committee compute their refreshed shares

	qualifiedDealers, lagrangeCoefs, err := ComputeQualifiedDealers(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute qualified dealers: %w", err)
	}
	myLog.Infof("qualified dealers: %v", qualifiedDealers)
	nextCommitments, err = ComputeRefreshedCommitments(pub, dealingMessages, qualifiedDealers, lagrangeCoefs)
	if indices.Next >= 0 {
		// We're in the next committee
		nextShare, err = ComputeRefreshedShare(
			pub, prv, indices.Next,
			dealingMessages, verificationMessages,
			qualifiedDealers, lagrangeCoefs,
		)
		if err != nil {
			return nil, nil, err
		}
	}

	return nextShare, nextCommitments, nil
}
