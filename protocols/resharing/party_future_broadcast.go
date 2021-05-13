package resharing

import (
	"fmt"
	"github.com/shaih/go-yosovss/primitives/shamir"
	"log"

	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/communication"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/pedersen"
)

// StartCommitteePartyFB initiates the protocol for party i participating in a t-of-n Pedersen VSS protocol using
// the future broadcast protocol
func StartCommitteePartyFB(
	bc communication.BroadcastChannel,
	pks []curve25519.PublicKey,
	sk curve25519.PrivateKey,
	psks []curve25519.PublicSignKey,
	ssk curve25519.PrivateSignKey,
	holdCommittee []int,
	verCommittee []int,
	fbCommittee []int,
	params *pedersen.Params,
	share *pedersen.Share,
	verifications []pedersen.Commitment,
	index int,
	t int,
	n int,
) error {

	holdIndex := intIndexOf(holdCommittee, index)
	verIndex := intIndexOf(verCommittee, index)
	fbIndex := intIndexOf(fbCommittee, index)

	// Repeat for fixed number of rounds
	for rounds := 0; rounds < 1; rounds++ {
		var v [][][]pedersen.Commitment
		var w [][][]pedersen.Commitment
		var e [][]pedersen.Commitment
		var symmEncB [][]curve25519.SymmetricCiphertext
		var symmEncD [][]curve25519.SymmetricCiphertext
		var fbShareEnc [][]curve25519.Ciphertext
		var complaints [][]bool

		// Get the committees for the next round
		nextHoldCommittee := NextCommitteeDeterministic(holdCommittee, len(pks))
		nextVerCommittee := NextCommitteeDeterministic(verCommittee, len(pks))
		nextFutureBroadcastCommittee := NextCommitteeDeterministic(fbCommittee, len(pks))
		nextHoldIndex := intIndexOf(nextHoldCommittee, index)
		nextVerIndex := intIndexOf(nextVerCommittee, index)
		nextFBIndex := intIndexOf(nextFutureBroadcastCommittee, index)

		// Participate in the holding committee
		if holdIndex >= 0 {
			err := HoldingCommitteeShareProtocolFB(bc, params, *share, pks, ssk, holdCommittee, verCommittee, fbCommittee,
				holdIndex, t, n)
			if err != nil {
				return fmt.Errorf("party %d failed to perform holding committee share protocol: %v", index, err)
			}
		} else {
			bc.Send([]byte{})
		}

		if verIndex >= 0 { // Party is member of the verification committee
			vNew, wNew, eNew, symmEncBNew, symmEncDNew, fbShareEncNew, err :=
				VerificationCommitteeProtocolFB(bc, pks[index], sk, params, holdCommittee, verIndex, n)
			if err != nil {
				return fmt.Errorf("party %d failed to perform verification committee protocol: %v", index, err)
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
			vNew, wNew, eNew, symmEncBNew, symmEncDNew, fbShareEncNew, err :=
				ReceiveHolderMessages(bc, holdCommittee, n)
			if err != nil {
				return fmt.Errorf("party %d failed to receive holder messages: %v", index, err)
			}
			v = vNew
			w = wNew
			e = eNew
			symmEncB = symmEncBNew
			symmEncD = symmEncDNew
			fbShareEnc = fbShareEncNew
		}

		complaints, err := ReceiveComplaints(bc, holdCommittee, verCommittee, holdIndex, n)
		if err != nil {
			return fmt.Errorf("party %d failed to receive complaints: %v", index, err)
		}

		if fbIndex >= 0 {
			err := FutureBroadcastCommitteeProtocol(bc, pks[index], sk, fbIndex, n, complaints, fbShareEnc)
			if err != nil {
				return fmt.Errorf("party %d failed to perform future broadcast protocol: %v", index, err)
			}
		} else {
			bc.Send([]byte{})
		}

		if nextHoldIndex >= 0 {
			s, v, err := HoldingCommitteeReceiveProtocolFB(bc, params, psks, v, w, e, holdCommittee, verCommittee,
				fbCommittee, nextHoldIndex, t, n, symmEncB, symmEncD, complaints)
			if err != nil {
				return fmt.Errorf("party %d failed to perform holding committee receive protocol: %v", index, err)
			}
			share = s
			verifications = v
		} else {
			bc.Send([]byte{})
		}

		// Move on to the next round of the protocol
		holdCommittee = nextHoldCommittee
		verCommittee = nextVerCommittee
		fbCommittee = nextFutureBroadcastCommittee
		holdIndex = nextHoldIndex
		verIndex = nextVerIndex
		fbIndex = nextFBIndex
	}

	// Final round to reconstruct message
	bc.Send(msgpack.Encode(share))

	_, roundMsgs := bc.ReceiveRound()

	var shares []pedersen.Share
	for i, holder := range holdCommittee {
		var share pedersen.Share
		err := msgpack.Decode(roundMsgs[holder].Payload, &share)
		if err != nil {
			return fmt.Errorf("decoding share from holder %d failed for holder %d: %v", i, holdIndex, err)
		}

		shares = append(shares, share)
	}

	// Reconstruct original message
	m, err := pedersen.VSSReconstruct(params, shares, verifications)
	if err != nil {
		return fmt.Errorf("failed to reconstruct original message for party %d: %v", index, err)
	}

	log.Printf("Party %d reconstructed message: %v", index, m)
	return nil
}

// HoldingCommitteeShareProtocol performs the actions of a party participating in the
// current holding committee for a round of the protocol, passing shares to the verification
// committee. It returns the verifications of the holders.
func HoldingCommitteeShareProtocolFB(
	bc communication.BroadcastChannel,
	params *pedersen.Params,
	share pedersen.Share,
	pks []curve25519.PublicKey,
	ssk curve25519.PrivateSignKey,
	holdCommittee []int,
	verCommittee []int,
	fbCommittee []int,
	holdIndex int,
	t int,
	n int,
) error {
	// Perform a two level share of s_i and r_i to get B_i matrix of shares and V_i matrix
	// of verifications for the secrets of the second level share and D_i and W_i for the decommitments of the second
	// level sharing. E_i is the verifications of the first level share,
	// where those shares are hidden (alpha_i vector as the hidden first level share vector)
	bi, vi, di, wi, ei, err := TwoLevelShare(params, share.S, share.R, t, n)
	if err != nil {
		return fmt.Errorf("error in creating shares of s_%d, r_%d: %v", holdIndex, holdIndex, err)
	}

	biEnc, err := EncryptSharesForVer(pks, bi, verCommittee)
	if err != nil {
		return fmt.Errorf("error in encrypting s_i shares: %v", holdIndex)
	}

	diEnc, err := EncryptSharesForVer(pks, di, verCommittee)
	if err != nil {
		return fmt.Errorf("error in encrypting r_i shares: %v", holdIndex)
	}

	bShares := make([][]pedersen.Share, n)
	dShares := make([][]pedersen.Share, n)

	for k := 0; k < n; k++ {
		bShares[k] = make([]pedersen.Share, n)
		dShares[k] = make([]pedersen.Share, n)
	}

	for j := 0; j < n; j++ {
		for k := 0; k < n; k++ {
			bShares[k][j] = bi[k][j]
			dShares[k][j] = di[k][j]
			fmt.Printf("BI(%d, %d, %d): %v \n", holdIndex, j ,k, bi[j][k])
		}
	}

	for j := 0; j < len(di); j++ {
		for k := 0; k < len(di[j]); k++ {
			fmt.Printf("DI(%d, %d, %d): %v \n", holdIndex, j ,k, di[j][k])
		}
	}

	// Future broadcast protocol
	keys := make([]curve25519.Key, n)
	symmEncBi := make([]curve25519.SymmetricCiphertext, n)
	symmEncDi := make([]curve25519.SymmetricCiphertext, n)
	fbKeyShares := make([][]shamir.Share, n)
	fbKeyShareSigs := make([][]curve25519.Signature, n)

	for l := 0; l < n; l++ {
		fbKeyShares[l] = make([]shamir.Share, n)
		fbKeyShareSigs[l] = make([]curve25519.Signature, n)
	}

	// Create symmetric keys for future broadcast
	for k := 0; k < n; k++ {
		keys[k] = curve25519.GenerateSymmetricKey()
		nonce := curve25519.Nonce([24]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

		symmEncBi[k], err = curve25519.SymmetricEncrypt(keys[k], nonce,
			curve25519.Message(msgpack.Encode(bShares[k])))
		if err != nil {
			return fmt.Errorf("error in encrypting s_i shares for future broadcast: %v", holdIndex)
		}

		symmEncDi[k], err = curve25519.SymmetricEncrypt(keys[k], nonce,
			curve25519.Message(msgpack.Encode(dShares[k])))
		if err != nil {
			return fmt.Errorf("error in encrypting r_i shares for future broadcast: %v", holdIndex)
		}

		fbShares, err := shamir.GenerateShares(shamir.Message(keys[k]), t, n)
		if err != nil {
			return fmt.Errorf("error in sharing future broadcast keys: %v", holdIndex)
		}

		for l := 0; l < n; l++ {
			fbKeyShares[l][k] = fbShares[l]
			sig, err := curve25519.Sign(ssk, msgpack.Encode(fbShares[l]))
			if err != nil {
				return fmt.Errorf("error in signing future broadcast shares: %v", holdIndex)
			}
			fbKeyShareSigs[l][k] = sig
		}
	}

	fbSharesEnc := make([]curve25519.Ciphertext, n)

	for l := 0; l < n; l++ {
		fbShare := FutureBroadcastShare {
			FBShares:    fbKeyShares[l],
			FBShareSigs: fbKeyShareSigs[l],
		}

		encFbShare, err := curve25519.Encrypt(pks[fbCommittee[l]], msgpack.Encode(fbShare))
		if err != nil {
			return fmt.Errorf("unable to encrypt future broadcast share using the public key of party %d", fbCommittee[l])
		}
		fbSharesEnc[l] = encFbShare

	}

	holdShareMsg := HoldShareFBMessage {
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

// VerificationCommitteeProtocolFB performs the actions of a party participating in the verification committee for a round
// of the protocol. It returns the verifications of the holders.
func VerificationCommitteeProtocolFB(
	bc communication.BroadcastChannel,
	pk curve25519.PublicKey,
	sk curve25519.PrivateKey,
	params *pedersen.Params,
	holdCommittee []int,
	verIndex int,
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

	bComplaints := make(map[int][]int)
	dComplaints := make(map[int][]int)

	bk := make([][]*pedersen.Share, n)
	dk := make([][]*pedersen.Share, n)

	for i := 0; i < n; i++ {
		bk[i] = make([]*pedersen.Share, n)
		dk[i] = make([]*pedersen.Share, n)
	}

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
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("decoding share from holder %d failed for verifier %d: %v", i, verIndex, err)
		}
		var holderBComplaints []int
		var holderDComplaints []int

		v[i] = make([][]pedersen.Commitment, n)
		w[i] = make([][]pedersen.Commitment, n)
		e[i] = make([]pedersen.Commitment, n)

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
			for j := 0; j < n; j++ {
				bIsValid, _ := pedersen.VSSVerify(params, bik[j], holdShareFbMsg.Vi[j])
				if bIsValid {
					bk[i][j] = &bik[j]
				} else {
					bk[i][j] = nil
					holderBComplaints = append(holderBComplaints, j)
				}
			}
		} else {
			for j := 0; j < n; j++ {
				bk[i][j] = nil
				holderBComplaints = append(holderBComplaints, j)
			}
		}

		if !dikFailed {
			// Construct matrix of complaints to broadcast for resolution of share of decommitments
			for j := 0; j < n; j++ {
				dIsValid, _ := pedersen.VSSVerify(params, dik[j], holdShareFbMsg.Wi[j])
				if dIsValid {
					dk[i][j] = &dik[j]
				} else {
					dk[i][j] = nil
					holderDComplaints = append(holderDComplaints, j)
				}
			}
		} else {
			for j := 0; j < n; j++ {
				dk[i][j] = nil
				holderDComplaints = append(holderDComplaints, j)
			}
		}

		bComplaints[i] = holderBComplaints
		dComplaints[i] = holderDComplaints
	}

	verShareMsgFB := VerShareMessageFB{
		Bk: bk,
		Dk: dk,
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
	holdCommittee []int,
	verCommittee []int,
	holdIndex int,
	n int,
) ([][]bool, error) {
	// complaints is a matrix of complaints where complaints[i][k] is true if there was a complaint filed for holder i
	// by verifier k
	complaints := make([][]bool, n)
	for i := 0; i <= n; i++ {
		complaints[i] = make([]bool, n)
	}

	_, roundMsgs := bc.ReceiveRound()

	// Iterate through message from the verification committee to get all the complaints filed
	for k, verifier := range verCommittee {
		var holderComplaintMsg HolderComplaintMessage
		err := msgpack.Decode(roundMsgs[verifier].Payload, &holderComplaintMsg)
		if err != nil {
			return nil, fmt.Errorf("failed to decode complaint of verifier %d for holder %d: %v", verifier, holdIndex, err)
		}

		for i, _ := range holdCommittee {
			if len(holderComplaintMsg.BComplaints[i]) > 0 {
				complaints[i][k] = true
			}
		}
	}

	return complaints, nil
}

// FutureBroadcastCommitteeProtocol performs the actions of the future broadcast committee in order to resolve
// complaints from the verification committee
func FutureBroadcastCommitteeProtocol(
	bc communication.BroadcastChannel,
	pk curve25519.PublicKey,
	sk curve25519.PrivateKey,
	fbIndex int,
	n int,
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

	fbResMsg := FutureBroadcastResponseMessage {
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
	params *pedersen.Params,
	psks []curve25519.PublicSignKey,
	v [][][]pedersen.Commitment,
	w [][][]pedersen.Commitment,
	e [][]pedersen.Commitment,
	holdCommittee []int,
	verCommittee []int,
	fbCommittee []int,
	nextHoldIndex int,
	t int,
	n int,
	symmEncB [][]curve25519.SymmetricCiphertext,
  	symmEncD [][]curve25519.SymmetricCiphertext,
	complaints [][]bool,
) (*pedersen.Share, []pedersen.Commitment, error) {

	_, roundMsgs := bc.ReceiveRound()

	bj := make([][]pedersen.Share, n)
	dj := make([][]pedersen.Share, n)
	for i := 0; i < n; i++ {
		bj[i] = make([]pedersen.Share, n)
		dj[i] = make([]pedersen.Share, n)
	}

	// Construct B_j matrix, the matrix of second level shares, from the verification committee or from
	// resolved complaints
	for k, verifier := range verCommittee {
		var verShareMsg VerShareMessage
		err := msgpack.Decode(roundMsgs[verifier].Payload, &verShareMsg)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding share from verifier %d failed for holder %d: %v", k, nextHoldIndex, err)
		}

		for i := 0; i < n; i++ {
			if verShareMsg.Bk[i][nextHoldIndex] != nil {
				bj[i][k] = *verShareMsg.Bk[i][nextHoldIndex]
			}
			if verShareMsg.Dk[i][nextHoldIndex] != nil {
				dj[i][k] = *verShareMsg.Dk[i][nextHoldIndex]
			}
		}
	}

	// Iterate through all of the complaints of a verifier k towards a holder i to obtain the appropriate shares
	for i := 0; i < n; i++ {
		for k := 0; k < n; k++ {
			if complaints[i][k] {
				var symmKeyReconstructShares []shamir.Share
				for l, fbParty := range fbCommittee {
					var fbResMsg FutureBroadcastResponseMessage
					err := msgpack.Decode(roundMsgs[fbParty].Payload, &fbResMsg)
					if err != nil {
						return nil, nil, fmt.Errorf("decoding share from future broadcast party %d failed: %v", l, err)
					}

					// Check if the share provided by a member of the future broadcast committee is the same as the one
					// handed out by the holder
					if curve25519.Verify(psks[holdCommittee[i]],
						curve25519.Message(msgpack.Encode(*fbResMsg.FBShares[i][k])), *fbResMsg.FBSigs[i][k]) {
						symmKeyReconstructShares = append(symmKeyReconstructShares, *fbResMsg.FBShares[i][k])
					}

					// Only t shares are required for reconstruction, so only collect the first t
					if len(symmKeyReconstructShares) == t {
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

	aj := make([]curve25519.Scalar, t)
	cj := make([]curve25519.Scalar, t)
	indicesScalar := make([]curve25519.Scalar, t)
	indices := make([]int, t)

	i := 0
	j := 0

	// Use the second level shares to reconstruct the first level shares
	for i < n && len(aj) < t {
		var bij []pedersen.Share
		var dij []pedersen.Share
		for k := 0; k < n; k++ {
			bij = append(bij, bj[i][k])
			dij = append(dij, dj[i][k])
		}
		aij, err1 := pedersen.VSSReconstruct(params, bij, v[i][nextHoldIndex])
		cij, err2 := pedersen.VSSReconstruct(params, dij, w[i][nextHoldIndex])
		if err1 == nil && err2 == nil { // Use corresponding shares of alpha and gamma
			aj = append(aj, curve25519.Scalar(*aij))
			cj = append(cj, curve25519.Scalar(*cij))
			indicesScalar[j] = curve25519.GetScalar(uint64(i + 1))
			indices[j] = i + 1
			j++
		}
		i++
	}

	// Return an error if we are unable to reconstruct at least t of the first level shares
	if len(aj) < t {
		return nil, nil, fmt.Errorf("unable to reconstruct sufficient alpha_i and gamma_i for holder %d", nextHoldIndex)
	}

	// Of the reconstructed shares, we take the first t of them and compute the Lagrange coefficients corresponding to
	// those shares
	lambdas, err := curve25519.LagrangeCoeffs(indicesScalar, curve25519.GetScalar(0))
	if err != nil {
		fmt.Printf("ERROR: %v\n", indicesScalar)

		return nil, nil, fmt.Errorf("unable to compute Lagrange coefficients for holder %d: %v", nextHoldIndex, err)
	}

	share := pedersen.Share{
		Index:       nextHoldIndex + 1,
		IndexScalar: curve25519.GetScalar(uint64(nextHoldIndex + 1)),
		S:           curve25519.ScalarZero,
		R:           curve25519.ScalarZero,
	}

	verifications := make([]pedersen.Commitment, t)

	for i := 0; i < t; i++ {
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
		isVerified, err := pedersen.VSSVerify(params, testShare, e[indices[i] - 1])
		if err != nil{
			return nil, nil, fmt.Errorf("unable to verify share %d: %v", nextHoldIndex, err)
		} else if !isVerified {
			return nil, nil, fmt.Errorf("share could not be verified %d: %v", nextHoldIndex, err)
		}
		// Computing the new verifications of the first level through doing the linear combination in the exponent
		for j := 0; j < t; j++ {
			prod, err := curve25519.MultPointScalar(curve25519.Point(e[indices[i] - 1][j]), lambdas[i])
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

	return &share, verifications, nil
}
