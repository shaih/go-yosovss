package resharing

import (
	"fmt"
	"log"

	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/communication"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
	"github.com/shaih/go-yosovss/primitives/shamir"
)

// StartCommitteePartyFB initiates the protocol for a party participating in a t-of-n Pedersen VSS protocol using
// the future broadcast protocol
// bc: the broadcast channel that connects the party to the orchestrator
// params: contains the parameters for the resharing protocol
// committees: contains the initial selections of which parties are in the holding, verification, and future broadcast
// committees
// sk: the secret key of the party that is used in public key encryption
// ssk: the secret signing key of the party. It is used for digital signatures
// share: if the party is initially party of the holding committee, share is the share from the initial dealing to the
// members of the first holding committee from the dealer. This is otherwise nil.
// verifications: the verifications of the first sharing that is broadcasted by the dealer
func StartCommitteePartyFB(
	bc communication.BroadcastChannel,
	params Params,
	committees Committees,
	sk curve25519.PrivateKey,
	ssk curve25519.PrivateSignKey,
	share *pedersen.Share,
	verifications []pedersen.Commitment,
	id int,
) error {

	// Compute the indices of the party in the various initial committees (-1 if not a part of a committee)
	indices := CommitteeIndices{
		Hold: intIndexOf(committees.Hold, id),
		Ver:  intIndexOf(committees.Ver, id),
		FB:   intIndexOf(committees.FB, id),
	}

	// Repeat for params.TotalRounds number of rounds of resharing
	for rounds := 0; rounds < params.TotalRounds; rounds++ {
		var v [][][]pedersen.Commitment
		var w [][][]pedersen.Commitment
		var e [][]pedersen.Commitment
		var symmEncB [][]curve25519.SymmetricCiphertext
		var symmEncD [][]curve25519.SymmetricCiphertext
		var fbShareEnc [][]curve25519.Ciphertext
		var complaints [][]bool
		var bjEnc []curve25519.Ciphertext
		var djEnc []curve25519.Ciphertext

		// Get the committees for the next round
		nextCommittees := Committees{
			Hold: NextCommitteeDeterministic(committees.Hold, len(params.Pks)),
			Ver:  NextCommitteeDeterministic(committees.Ver, len(params.Pks)),
			FB:   NextCommitteeDeterministic(committees.FB, len(params.Pks)),
		}

		// Get the indices of the party for the next round
		nextIndices := CommitteeIndices{
			Hold: intIndexOf(nextCommittees.Hold, id),
			Ver:  intIndexOf(nextCommittees.Ver, id),
			FB:   intIndexOf(nextCommittees.FB, id),
		}

		// Participate in the holding committee. The holding committee performs the two level sharing and sends shares
		// to the verification committee.
		if indices.Hold >= 0 {
			err := HoldingCommitteeShareProtocolFB(bc, params, committees, indices.Hold, *share, ssk)
			if err != nil {
				return fmt.Errorf("party %d failed to perform holding committee share protocol: %v", id, err)
			}
		} else { // Do nothing if not part of the holding committee
			bc.Send([]byte{})
		}

		// Participate in the verification committee. The verification committee checks the validity of the shares
		// sent by the holding committee, sends them to the next holding committee, and also files complaints against
		// invalid shares.
		if indices.Ver >= 0 {
			vNew, wNew, eNew, symmEncBNew, symmEncDNew, fbShareEncNew, err :=
				VerificationCommitteeProtocolFB(bc, params, committees, nextCommittees.Hold, indices.Ver,
					params.Pks[id], sk)
			if err != nil {
				return fmt.Errorf("party %d failed to perform verification committee protocol: %v", id, err)
			}
			v = vNew
			w = wNew
			e = eNew
			symmEncB = symmEncBNew
			symmEncD = symmEncDNew
			fbShareEnc = fbShareEncNew
			if err != nil {
				return fmt.Errorf("error in verification committee protocol: %v", err)
			}
		} else {
			// If not part of the verification committee, a party still needs to receive the verifications (v, w, e)
			// that are broadcasted by the dealer in the two level sharing.
			// The party also gets symmEncB and symmEncD, the symmetrically encrypted shares created by the dealer that
			// is unlocked by the future broadcast committee, and also fbShareEnc, the shares to the future broadcast
			// committee in case the party is also a part of the future broadcast committee.
			vNew, wNew, eNew, symmEncBNew, symmEncDNew, fbShareEncNew, err :=
				ReceiveHolderMessages(bc, committees.Hold, params.N)
			if err != nil {
				return fmt.Errorf("party %d failed to receive holder messages: %v", id, err)
			}
			v = vNew
			w = wNew
			e = eNew
			symmEncB = symmEncBNew
			symmEncD = symmEncDNew
			fbShareEnc = fbShareEncNew
			bc.Send([]byte{})
		}

		// Every party listens to the complaints by the verification committee to obtain complaints, where
		// complaints[i][k] is true if there was a complaint filed for holding committee member i by verification
		// committee member k. The party also listens for bjEnc and djEnc, the encrypted shares for holding committee
		// member j in case that the party will be participating in the next holding committee.
		complaints, bjEnc, djEnc, err := ReceiveComplaints(bc, committees, indices, params.N)
		if err != nil {
			return fmt.Errorf("party %d failed to receive complaints: %v", id, err)
		}

		// Participate in the future broadcast committee. For each verifier k that complained against holder i, the
		// members of the future broadcast committee reveal their Shamir share to the symmetric key k_{ik} in order
		// to reconstruct the key and reveal the shares committed to by the dealer.
		if indices.FB >= 0 {
			err := FutureBroadcastCommitteeProtocol(bc, params.N, params.Pks[id], sk, indices.FB, complaints, fbShareEnc)
			if err != nil {
				return fmt.Errorf("party %d failed to perform future broadcast protocol: %v", id, err)
			}
		} else { // do nothing if not in future broadcast committee
			bc.Send([]byte{})
		}

		// Participate in the holding committee of the next round in order to construct the new set of shares for the
		// next round of resharing. Each member receives shares from the verification committee and also uses the
		// revealed shares of the future broadcast committee to resolve complaints. This ultimately gives the party
		// enough second level shares to reconstruct the first level shares meant for the party, and then interpolate
		// the share for the next round.
		if nextIndices.Hold >= 0 {
			s, v, err := HoldingCommitteeReceiveProtocolFB(bc, params, committees, nextIndices.Hold, params.Pks[id], sk,
				v, w, e, symmEncB, symmEncD, complaints, bjEnc, djEnc)
			if err != nil {
				return fmt.Errorf("party %d failed to perform holding committee receive protocol: %v", id, err)
			}
			share = s
			verifications = v
		} else {
			// Those not participating in the next holding committee still need to obtain the top level verifications
			// for the next round of resharing
			bc.ReceiveRound()
			bc.Send([]byte{})
			v, err := ReceiveNextVerifications(bc, nextCommittees.Hold)
			if err != nil {
				return fmt.Errorf("party %d failed to obtain the verifications for the next round: %v", id, err)
			}
			verifications = v
		}

		// Move on to the next round of the protocol
		committees = nextCommittees
		indices = nextIndices
	}

	// After the specified number of rounds of resharing, there is a final broadcast by everyone to reconstruct message
	bc.Send(msgpack.Encode(share))
	_, roundMsgs := bc.ReceiveRound()

	// Collect shares from the holding committee in the last round of the protocol
	var shares []pedersen.Share
	for i, holder := range committees.Hold {
		var share pedersen.Share
		err := msgpack.Decode(roundMsgs[holder].Payload, &share)
		if err != nil {
			return fmt.Errorf("decoding share from holder %d failed for party %d: %v", i, id, err)
		}

		shares = append(shares, share)
	}

	// Reconstruct original message
	m, err := pedersen.VSSReconstruct(params.PedersenParams, shares, verifications)
	if err != nil {
		return fmt.Errorf("failed to reconstruct original message for party %d: %v", id, err)
	}

	log.Printf("Party %d reconstructed message: %v", id, m)
	return nil
}

// HoldingCommitteeShareProtocol performs the actions of a party participating in the
// current holding committee for a round of the protocol, passing shares to the verification
// committee. It returns the verifications of the holders.
func HoldingCommitteeShareProtocolFB(
	bc communication.BroadcastChannel,
	params Params,
	committees Committees,
	holdIndex int,
	share pedersen.Share,
	ssk curve25519.PrivateSignKey,
) error {
	// Perform a two level share of s_i and r_i to get B_i matrix of shares and V_i matrix
	// of verifications for the secrets of the second level share and D_i and W_i for the decommitments of the second
	// level sharing. E_i is the verifications of the first level share,
	// where those shares are hidden (alpha_i vector as the hidden first level share vector)
	bi, vi, di, wi, ei, err := TwoLevelShare(params.PedersenParams, share.S, share.R, params.T, params.N)
	if err != nil {
		return fmt.Errorf("error in creating shares of s_%d, r_%d: %v", holdIndex, holdIndex, err)
	}

	biEnc, err := EncryptSharesForVer(params.Pks, bi, committees.Ver)
	if err != nil {
		return fmt.Errorf("error in encrypting s_i shares: %v", holdIndex)
	}

	diEnc, err := EncryptSharesForVer(params.Pks, di, committees.Ver)
	if err != nil {
		return fmt.Errorf("error in encrypting r_i shares: %v", holdIndex)
	}

	bShares := make([][]pedersen.Share, params.N)
	dShares := make([][]pedersen.Share, params.N)

	for k := 0; k < params.N; k++ {
		bShares[k] = make([]pedersen.Share, params.N)
		dShares[k] = make([]pedersen.Share, params.N)
	}

	// Future broadcast protocol
	keys := make([]curve25519.Key, params.N)
	symmEncBi := make([]curve25519.SymmetricCiphertext, params.N)
	symmEncDi := make([]curve25519.SymmetricCiphertext, params.N)
	fbKeyShares := make([][]shamir.Share, params.N)
	fbKeyShareSigs := make([][]curve25519.Signature, params.N)

	for l := 0; l < params.N; l++ {
		fbKeyShares[l] = make([]shamir.Share, params.N)
		fbKeyShareSigs[l] = make([]curve25519.Signature, params.N)
	}

	// Create symmetric keys for future broadcast to encrypt B_ik vectors
	for k := 0; k < params.N; k++ {
		keys[k] = curve25519.GenerateSymmetricKey()
		nonce := curve25519.Nonce([24]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

		// Encrypt B_ik vector using key k
		symmEncBi[k], err = curve25519.SymmetricEncrypt(keys[k], nonce,
			curve25519.Message(msgpack.Encode(bShares[k])))
		if err != nil {
			return fmt.Errorf("error in encrypting s_i shares for future broadcast: %v", holdIndex)
		}

		// Encrypt D_ik vector using key k
		symmEncDi[k], err = curve25519.SymmetricEncrypt(keys[k], nonce,
			curve25519.Message(msgpack.Encode(dShares[k])))
		if err != nil {
			return fmt.Errorf("error in encrypting r_i shares for future broadcast: %v", holdIndex)
		}

		// Perform t-of-n Shamir Secret sharing on the symmetric keys to distribute to the future broadcast committee
		fbShares, err := shamir.GenerateShares(shamir.Message(keys[k]), params.T, params.N)
		if err != nil {
			return fmt.Errorf("error in sharing future broadcast keys: %v", holdIndex)
		}

		// For each future broadcast committee member l, give them one share of each of the k keys, along with a
		// signature of of the key to show its validity from the holder.
		for l := 0; l < params.N; l++ {
			fbKeyShares[l][k] = fbShares[l]
			sig, err := curve25519.Sign(ssk, msgpack.Encode(fbShares[l]))
			if err != nil {
				return fmt.Errorf("error in signing future broadcast shares: %v", holdIndex)
			}
			fbKeyShareSigs[l][k] = sig
		}
	}

	fbSharesEnc := make([]curve25519.Ciphertext, params.N)

	for l := 0; l < params.N; l++ {
		fbShare := FutureBroadcastShare{
			FBShares:    fbKeyShares[l],
			FBShareSigs: fbKeyShareSigs[l],
		}

		// Encrypt the future broadcast shares so only FB committee member l can decrypt the message containing
		// the shamir shares s_ikl
		encFbShare, err := curve25519.Encrypt(params.Pks[committees.FB[l]], msgpack.Encode(fbShare))
		if err != nil {
			return fmt.Errorf("unable to encrypt future broadcast share using the public key of future broadcast member %d", l)
		}
		fbSharesEnc[l] = encFbShare

	}

	holdShareMsg := HoldShareFBMessage{
		BiEnc:       biEnc,
		Vi:          vi,
		DiEnc:       diEnc,
		Wi:          wi,
		Ei:          ei,
		SymmEncBi:   symmEncBi,
		SymmEncDi:   symmEncDi,
		FBShareiEnc: fbSharesEnc,
	}

	// Send shares to verification committee
	bc.Send(msgpack.Encode(holdShareMsg))

	return nil
}

// ReceiveHolderMessages receives the round of the protocol after the holding committee has constructed shares and
// extracts the verification commitments and future broadcast data from the messages
func ReceiveHolderMessages(
	bc communication.BroadcastChannel,
	holdCommittee []int,
	n int,
) (
	[][][]pedersen.Commitment,
	[][][]pedersen.Commitment,
	[][]pedersen.Commitment,
	[][]curve25519.SymmetricCiphertext,
	[][]curve25519.SymmetricCiphertext,
	[][]curve25519.Ciphertext,
	error,
) {
	// Receive shares from holding committee
	_, roundMsgs := bc.ReceiveRound()
	v := make([][][]pedersen.Commitment, n)
	w := make([][][]pedersen.Commitment, n)
	e := make([][]pedersen.Commitment, n)
	symmEncB := make([][]curve25519.SymmetricCiphertext, n)
	symmEncD := make([][]curve25519.SymmetricCiphertext, n)
	fbShareEnc := make([][]curve25519.Ciphertext, n)

	// Checks validity of shares and construct beta_k matrix
	for i, holder := range holdCommittee {
		var holdShareFbMsg HoldShareFBMessage
		err := msgpack.Decode(roundMsgs[holder].Payload, &holdShareFbMsg)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("decoding share from holder %d failed: %v", i, err)
		}

		v[i] = holdShareFbMsg.Vi
		w[i] = holdShareFbMsg.Wi
		e[i] = holdShareFbMsg.Ei
		symmEncB[i] = holdShareFbMsg.SymmEncBi
		symmEncD[i] = holdShareFbMsg.SymmEncDi
		fbShareEnc[i] = holdShareFbMsg.FBShareiEnc
	}

	return v, w, e, symmEncB, symmEncD, fbShareEnc, nil
}

// VerificationCommitteeProtocolFB performs the actions of a party participating in the verification committee for a
// round of the protocol. It returns the verifications of the holders.
func VerificationCommitteeProtocolFB(
	bc communication.BroadcastChannel,
	params Params,
	committees Committees,
	nextHoldCommittee []int,
	verIndex int,
	pk curve25519.PublicKey,
	sk curve25519.PrivateKey,
) (
	[][][]pedersen.Commitment,
	[][][]pedersen.Commitment,
	[][]pedersen.Commitment,
	[][]curve25519.SymmetricCiphertext,
	[][]curve25519.SymmetricCiphertext,
	[][]curve25519.Ciphertext,
	error,
) {
	// Receive shares from holding committee
	_, roundMsgs := bc.ReceiveRound()

	bComplaints := make(map[int][]int)
	dComplaints := make(map[int][]int)

	bk := make([][]*pedersen.Share, params.N)
	dk := make([][]*pedersen.Share, params.N)

	for j := 0; j < params.N; j++ {
		bk[j] = make([]*pedersen.Share, params.N)
		dk[j] = make([]*pedersen.Share, params.N)
	}

	v := make([][][]pedersen.Commitment, params.N)
	w := make([][][]pedersen.Commitment, params.N)
	e := make([][]pedersen.Commitment, params.N)
	symmEncB := make([][]curve25519.SymmetricCiphertext, params.N)
	symmEncD := make([][]curve25519.SymmetricCiphertext, params.N)
	fbShareEnc := make([][]curve25519.Ciphertext, params.N)

	// Checks validity of shares and construct beta_k matrix
	for i, holder := range committees.Hold {
		var holdShareFbMsg HoldShareFBMessage
		err := msgpack.Decode(roundMsgs[holder].Payload, &holdShareFbMsg)
		if err != nil {
			return nil, nil, nil, nil, nil, nil,
				fmt.Errorf("decoding share from holder %d failed for verifier %d: %v", i, verIndex, err)
		}
		var holderBComplaints []int
		var holderDComplaints []int

		v[i] = make([][]pedersen.Commitment, params.N)
		w[i] = make([][]pedersen.Commitment, params.N)
		e[i] = make([]pedersen.Commitment, params.N)

		bikFailed := false
		dikFailed := false

		// Decrypt shares from the holding committee
		bikBytes, err := curve25519.Decrypt(pk, sk, holdShareFbMsg.BiEnc[verIndex])
		var bik []pedersen.Share
		if err != nil {
			bikFailed = true
		} else {
			// Decode decrypted shares from the holding committee
			err = msgpack.Decode(bikBytes, &bik)
			if err != nil {
				bikFailed = true
			}
		}

		dikBytes, err := curve25519.Decrypt(pk, sk, holdShareFbMsg.DiEnc[verIndex])
		var dik []pedersen.Share
		if err != nil {
			dikFailed = true
		} else {

			err = msgpack.Decode(dikBytes, &dik)
			if err != nil {
				dikFailed = true
			}
		}

		// Get verifications from the holding committee
		v[i] = holdShareFbMsg.Vi
		w[i] = holdShareFbMsg.Wi
		e[i] = holdShareFbMsg.Ei
		symmEncB[i] = holdShareFbMsg.SymmEncBi
		symmEncD[i] = holdShareFbMsg.SymmEncDi
		fbShareEnc[i] = holdShareFbMsg.FBShareiEnc

		if !bikFailed {
			// Construct matrix of complaints to broadcast for resolution of share of shares
			for j := 0; j < params.N; j++ {
				bIsValid, _ := pedersen.VSSVerify(params.PedersenParams, bik[j], holdShareFbMsg.Vi[j])
				if bIsValid {
					bk[j][i] = &bik[j]
				} else {
					bk[j][i] = nil
					holderBComplaints = append(holderBComplaints, j)
				}
			}
		} else {
			for j := 0; j < params.N; j++ {
				bk[j][i] = nil
				holderBComplaints = append(holderBComplaints, j)
			}
		}

		if !dikFailed {
			// Construct matrix of complaints to broadcast for resolution of share of decommitments
			for j := 0; j < params.N; j++ {
				dIsValid, _ := pedersen.VSSVerify(params.PedersenParams, dik[j], holdShareFbMsg.Wi[j])
				if dIsValid {
					dk[j][i] = &dik[j]
				} else {
					dk[j][i] = nil
					holderDComplaints = append(holderDComplaints, j)
				}
			}
		} else {
			for j := 0; j < params.N; j++ {
				dk[j][i] = nil
				holderDComplaints = append(holderDComplaints, j)
			}
		}

		bComplaints[i] = holderBComplaints
		dComplaints[i] = holderDComplaints
	}

	bkEnc := make([]curve25519.Ciphertext, params.N)
	dkEnc := make([]curve25519.Ciphertext, params.N)

	// Encrypt the messages from the verification committee member k to next holding committee member j
	for j := 0; j < params.N; j++ {
		bjkEnc, err := curve25519.Encrypt(params.Pks[nextHoldCommittee[j]], msgpack.Encode(bk[j]))
		if err != nil {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("unable to encrypt using the public key of party %d", nextHoldCommittee[j])
		}
		bkEnc[j] = bjkEnc

		djkEnc, err := curve25519.Encrypt(params.Pks[nextHoldCommittee[j]], msgpack.Encode(dk[j]))
		if err != nil {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("unable to encrypt using the public key of party %d", nextHoldCommittee[j])
		}
		dkEnc[j] = djkEnc

	}

	verShareMsgFB := VerShareMessageFB{
		BkEnc:       bkEnc,
		DkEnc:       dkEnc,
		BComplaints: bComplaints,
		DComplaints: dComplaints,
	}

	// Broadcast complaints and send shares to the next holding committee
	bc.Send(msgpack.Encode(verShareMsgFB))

	return v, w, e, symmEncB, symmEncD, fbShareEnc, nil
}

// ReceiveComplaints gets the complaint broadcasts from the verification committee and creates a matrix of which
// complaints were filed
func ReceiveComplaints(
	bc communication.BroadcastChannel,
	committees Committees,
	nextIndices CommitteeIndices,
	n int,
) ([][]bool, []curve25519.Ciphertext, []curve25519.Ciphertext, error) {
	// complaints is a matrix of complaints where complaints[i][k] is true if there was a complaint filed for holder i
	// by verifier k
	complaints := make([][]bool, n)

	var bjEnc []curve25519.Ciphertext
	var djEnc []curve25519.Ciphertext

	// Track the encrypted shares if the party is going to be in the next holding committee
	if nextIndices.Hold >= 0 {
		bjEnc = make([]curve25519.Ciphertext, n)
		djEnc = make([]curve25519.Ciphertext, n)
	} else {
		bjEnc = nil
		djEnc = nil
	}

	for i := 0; i < n; i++ {
		complaints[i] = make([]bool, n)
	}

	_, roundMsgs := bc.ReceiveRound()

	// Iterate through message from the verification committee to get all the complaints filed
	for k, verifier := range committees.Ver {
		var verShareMsgFB VerShareMessageFB
		err := msgpack.Decode(roundMsgs[verifier].Payload, &verShareMsgFB)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decode complaints of verifier %d: %v", k, err)
		}

		for i := range committees.Hold {
			if len(verShareMsgFB.BComplaints[i]) > 0 {
				complaints[i][k] = true
			}
		}

		// Get the shares if participating in the next holding committee, but only the ones relevant to the party
		if nextIndices.Hold >= 0 {
			bjEnc[k] = verShareMsgFB.BkEnc[nextIndices.Hold]
			djEnc[k] = verShareMsgFB.DkEnc[nextIndices.Hold]
		}
	}

	return complaints, bjEnc, djEnc, nil
}

// FutureBroadcastCommitteeProtocol performs the actions of the future broadcast committee in order to resolve
// complaints from the verification committee
func FutureBroadcastCommitteeProtocol(
	bc communication.BroadcastChannel,
	n int,
	pk curve25519.PublicKey,
	sk curve25519.PrivateKey,
	fbIndex int,
	complaints [][]bool,
	fbShareEnc [][]curve25519.Ciphertext,
) error {
	// A list of the future broadcast shares for future broadcast party l from each holder i of the symmetric key to
	// sign the shares of verifier k
	fblShares := make([][]shamir.Share, n)
	// A list of the future broadcast share signatures for future broadcast party l from each holder i of the share to
	// the symmetric key to sign the shares of verifier k
	fblSigs := make([][]curve25519.Signature, n)

	// Checks validity of shares and construct beta_k matrix
	for i := 0; i < n; i++ { // Iterate through each message from the holder
		var fbShare FutureBroadcastShare
		fbShareBytes, err := curve25519.Decrypt(pk, sk, fbShareEnc[i][fbIndex])
		if err != nil {
			return fmt.Errorf("decrypting future broadcast from holder %d failed: %v", i, err)
		}
		err = msgpack.Decode(fbShareBytes, &fbShare)
		if err != nil {
			return fmt.Errorf("decoding future broadcast message from holder %d failed: %v", i, err)
		}

		fblShares[i] = fbShare.FBShares
		fblSigs[i] = fbShare.FBShareSigs
	}

	// Initialize n x n matrix of nil shares, to be populated with future broadcast shares to respond to complaints
	fbShareRes := make([][]*shamir.Share, n)
	for i := 0; i < n; i++ {
		fbShareRes[i] = make([]*shamir.Share, n)
	}

	// Initialize n x n matrix of nil shares, to be populated to respond future broadcast share signatures to complaints
	fbSigRes := make([][]*curve25519.Signature, n)
	for i := 0; i < n; i++ {
		fbSigRes[i] = make([]*curve25519.Signature, n)
	}

	// Broadcast shares to reconstruct the symmetric key corresponding to the complaints
	for i := 0; i < n; i++ {
		for k := 0; k < n; k++ {
			if complaints[i][k] {
				fbShareRes[i][k] = &fblShares[i][k]
				fbSigRes[i][k] = &fblSigs[i][k]
			}
		}
	}

	fbResMsg := FutureBroadcastResponseMessage{
		FBShares: fbShareRes,
		FBSigs:   fbSigRes,
	}

	// Send out shares to reconstruct symmetric keys
	bc.Send(msgpack.Encode(fbResMsg))

	return nil
}

// HoldingCommitteeReceiveProtocolFB performs the actions of a party participating in the next holding committee for a
// round of the protocol, receiving shares from the verification committee
func HoldingCommitteeReceiveProtocolFB(
	bc communication.BroadcastChannel,
	params Params,
	committees Committees,
	nextHoldIndex int,
	pk curve25519.PublicKey,
	sk curve25519.PrivateKey,
	v [][][]pedersen.Commitment,
	w [][][]pedersen.Commitment,
	e [][]pedersen.Commitment,
	symmEncB [][]curve25519.SymmetricCiphertext,
	symmEncD [][]curve25519.SymmetricCiphertext,
	complaints [][]bool,
	bjEnc []curve25519.Ciphertext,
	djEnc []curve25519.Ciphertext,
) (*pedersen.Share, []pedersen.Commitment, error) {
	_, roundMsgs := bc.ReceiveRound()

	bj := make([][]pedersen.Share, params.N)
	dj := make([][]pedersen.Share, params.N)
	for i := 0; i < params.N; i++ {
		bj[i] = make([]pedersen.Share, params.N)
		dj[i] = make([]pedersen.Share, params.N)
	}

	fmt.Printf("asdf: %v \n", bjEnc)

	// Construct B_j matrix, the matrix of second level shares, from the verification committee or from
	// resolved complaints
	for k := 0; k < params.N; k++ {
		// Decrypt shares from the holding committee
		bjkBytes, err := curve25519.Decrypt(pk, sk, bjEnc[k])
		var bjk []pedersen.Share
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt shares from verifier %d to holder %d: %v", k, nextHoldIndex, err)
		}

		// Decode decrypted shares from the holding committee
		err = msgpack.Decode(bjkBytes, &bjk)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode shares from verifier %d to holder %d: %v", k, nextHoldIndex, err)
		}

		djkBytes, err := curve25519.Decrypt(pk, sk, djEnc[k])
		var djk []pedersen.Share
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt shares from verifier %d to holder %d: %v", k, nextHoldIndex, err)
		}

		err = msgpack.Decode(djkBytes, &djk)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode shares from verifier %d to holder %d: %v", k, nextHoldIndex, err)
		}

		for i := 0; i < params.N; i++ {
			bj[i][k] = bjk[i]
			dj[i][k] = djk[i]
		}
	}

	// Iterate through all of the complaints of a verifier k towards a holder i to obtain the appropriate shares
	for i := 0; i < params.N; i++ {
		for k := 0; k < params.N; k++ {
			if complaints[i][k] {
				var symmKeyReconstructShares []shamir.Share
				for l, fbParty := range committees.FB {
					var fbResMsg FutureBroadcastResponseMessage
					err := msgpack.Decode(roundMsgs[fbParty].Payload, &fbResMsg)
					if err != nil {
						return nil, nil, fmt.Errorf("decoding share from future broadcast party %d failed: %v", l, err)
					}

					// Check if the share provided by a member of the future broadcast committee is the same as the one
					// handed out by the holder
					if curve25519.Verify(params.Psks[committees.Hold[i]],
						curve25519.Message(msgpack.Encode(*fbResMsg.FBShares[i][k])), *fbResMsg.FBSigs[i][k]) {
						symmKeyReconstructShares = append(symmKeyReconstructShares, *fbResMsg.FBShares[i][k])
					}

					// Only t shares are required for reconstruction, so only collect the first t
					if len(symmKeyReconstructShares) == params.T {
						break
					}
				}

				// Reconstruct the symmetric key
				symmKey, err := shamir.Reconstruct(symmKeyReconstructShares)
				if err != nil {
					return nil, nil, fmt.Errorf("unable to reconstruct the symmetric key for holder %d and verifier %d: %v", i, k, err)
				}

				// Use the symmetric key to decrypt the shares originally encrypted by the holding committee
				nonce := curve25519.Nonce([24]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
				bikSharesBytes, err := curve25519.SymmetricDecrypt(curve25519.Key(*symmKey), nonce, symmEncB[i][k])
				if err != nil {
					return nil, nil, fmt.Errorf("unable to decrypt symmetric encrypted shares for holder %d and verifier %d: %v", i, k, err)
				}

				dikSharesBytes, err := curve25519.SymmetricDecrypt(curve25519.Key(*symmKey), nonce, symmEncD[i][k])
				if err != nil {
					return nil, nil, fmt.Errorf("unable to decrypt symmetric encrypted shares for holder %d and verifier %d: %v", i, k, err)
				}

				// Decode the list of shares
				var bikShares []pedersen.Share
				err = msgpack.Decode(bikSharesBytes, &bikShares)
				if err != nil {
					return nil, nil, fmt.Errorf("unable to decode symmetric encrypted shares for holder %d and verifier %d: %v", i, k, err)
				}

				var dikShares []pedersen.Share
				err = msgpack.Decode(dikSharesBytes, &dikShares)
				if err != nil {
					return nil, nil, fmt.Errorf("unable to decode symmetric encrypted shares for holder %d and verifier %d: %v", i, k, err)
				}

				bj[i][k] = bikShares[nextHoldIndex]
				dj[i][k] = dikShares[nextHoldIndex]
			}
		}
	}

	var aj []curve25519.Scalar
	var cj []curve25519.Scalar
	var indicesScalar []curve25519.Scalar
	var indices []int

	i := 0
	// Use the second level shares to reconstruct the first level shares
	for i < params.N && len(aj) < params.T {
		var bij []pedersen.Share
		var dij []pedersen.Share
		for k := 0; k < params.N; k++ {
			bij = append(bij, bj[i][k])
			dij = append(dij, dj[i][k])
		}
		aij, err1 := pedersen.VSSReconstruct(params.PedersenParams, bij, v[i][nextHoldIndex])
		cij, err2 := pedersen.VSSReconstruct(params.PedersenParams, dij, w[i][nextHoldIndex])

		// If the reconstruction of the first level share was successful, we add it to the set of valid shares to
		// create the share for the next round
		if err1 == nil && err2 == nil { // Use corresponding shares of alpha and gamma
			aj = append(aj, curve25519.Scalar(*aij))
			cj = append(cj, curve25519.Scalar(*cij))
			indicesScalar = append(indicesScalar, curve25519.GetScalar(uint64(i+1))) // Track the index of the successful share
			indices = append(indices, i+1)
		}
		i++
	}

	// Return an error if we are unable to reconstruct at least t of the first level shares
	if len(aj) < params.T {
		return nil, nil, fmt.Errorf("unable to reconstruct sufficient alpha_i and gamma_i for holder %d", nextHoldIndex)
	}

	// Of the reconstructed shares, we take the first t of them and compute the Lagrange coefficients corresponding to
	// those shares
	lambdas, err := curve25519.LagrangeCoeffs(indicesScalar, curve25519.GetScalar(0))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to compute Lagrange coefficients for holder %d: %v", nextHoldIndex, err)
	}

	// Construction of the share for the next round of resharng protocol. The shares are initialized to zero and then
	// constructed iteratively below using the linear combination of current shares.
	share := pedersen.Share{
		Index:       nextHoldIndex + 1,
		IndexScalar: curve25519.GetScalar(uint64(nextHoldIndex + 1)),
		S:           curve25519.ScalarZero,
		R:           curve25519.ScalarZero,
	}

	verifications := make([]pedersen.Commitment, params.T)

	for i := 0; i < params.T; i++ {
		// Computing the linear combination of the previous shares with Lagrange coefficients to construct share
		// for the next round of the protocol.
		share.S = curve25519.AddScalar(share.S, curve25519.MultScalar(lambdas[i], aj[i]))
		share.R = curve25519.AddScalar(share.R, curve25519.MultScalar(lambdas[i], cj[i]))
		testShare := pedersen.Share{
			Index:       nextHoldIndex + 1,
			IndexScalar: curve25519.GetScalar(uint64(nextHoldIndex + 1)),
			S:           aj[i],
			R:           cj[i],
		}

		// Verification of the first level share using the E matrix to confirm validity of the first level
		isVerified, err := pedersen.VSSVerify(params.PedersenParams, testShare, e[indices[i]-1])
		if err != nil {
			return nil, nil, fmt.Errorf("unable to verify share %d: %v", nextHoldIndex, err)
		} else if !isVerified {
			return nil, nil, fmt.Errorf("share could not be verified %d: %v", nextHoldIndex, err)
		}
		// Computing the new verifications of the first level through doing the linear combination in the exponent
		for j := 0; j < params.T; j++ {
			prod, err := curve25519.MultPointScalar(curve25519.Point(e[indices[i]-1][j]), lambdas[i])
			if err != nil {
				return nil, nil, fmt.Errorf("unable to compute new verifications %d: %v", nextHoldIndex, err)
			}
			var sum curve25519.Point
			if i == 0 {
				sum = prod
			} else {
				sum, err = curve25519.AddPoint(curve25519.Point(verifications[j]), prod)
				if err != nil {
					return nil, nil, fmt.Errorf("unable to compute new verifications %d: %v", nextHoldIndex, err)
				}
			}
			verifications[j] = pedersen.Commitment(sum)
		}
	}

	// broadcast new verifications to save from every party needing to compute
	bc.Send(msgpack.Encode(verifications))
	bc.ReceiveRound()

	return &share, verifications, nil
}

// ReceiveNextVerifications performs the actions of a party not in the holding committee that needs to obtain the
// verifications for the next round of resharing
func ReceiveNextVerifications(
	bc communication.BroadcastChannel,
	nextHoldCommittee []int,
) ([]pedersen.Commitment, error) {
	_, roundMsgs := bc.ReceiveRound()

	var verifications []pedersen.Commitment
	for _, holder := range nextHoldCommittee {
		var ver []pedersen.Commitment
		err := msgpack.Decode(roundMsgs[holder].Payload, &ver)
		if err == nil {
			verifications = ver
		}
	}

	return verifications, nil
}
