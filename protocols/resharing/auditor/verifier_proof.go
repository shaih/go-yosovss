package auditor

import (
	"crypto/sha256"
	"fmt"

	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
	"github.com/shaih/go-yosovss/primitives/feldman"
)

// This file is to handle the proof made by each verifier V_j
// j is fixed in all the file
// i may not go from 0 to n-1 in this file as some dealers may be disqualified
// Let m be the number of qualified dealers
// To simplify the comments, we suppose that i = 0, ..., m-1
// but in practice this may not be those m indices

type VPCommitProof struct {
	ComR     []curve25519.PointXY `codec:"c"` // ComR[l] = sum_i e_ij sigma_ijl G_l, l in [0,n]
	DLProofR DLProof              `codec:"p"` // DLProofR is a proof that ComR[l] = rho'_l G_l, l in [0,n]
	HashL    [][HashLength]byte   `codec:"h"` // HashL = Hash(sigma_ijl for l in [0,n])
	// TODO: ACTUALLY WE don't need the hash for l = 0 but it's fine
}

type VPHashLIn struct {
	SigmaL []curve25519.Scalar `codec:"s"` // SigmaL[i] = sigma_ijl, where l is fixed - size = m scalars
}

type VPHashEIn struct {
	HashL [][HashLength]byte `codec:"h"`
}

// VPCommitAndProve generates a commitment vpcp.comR and a proof of validity of this commitment
// for sigma defined as sigma[i][j] = sigma_ijl
// where j is the index of the verifier making the call
// and i is in 0,...,m-1
// See comment at top of file
func VPCommitAndProve(vcParams *feldman.VCParams, sigma [][]curve25519.Scalar) (
	vpcp VPCommitProof, err error) {

	n := vcParams.N
	m := len(sigma)

	sigmaTranspose := vpComputeSigmaTranspose(sigma)

	vpcp.HashL = vpCommitAndProveComputeHashL(sigmaTranspose)

	e := VPComputeHashE(VPHashEIn{HashL: vpcp.HashL}, m)

	// Compute comR and their log
	comRLog := make([]curve25519.Scalar, n+1)
	comR := make([]curve25519.PointXY, n+1)

	for l := 0; l <= n; l++ {
		cLog, err := vpComputeComRLLog(e, sigmaTranspose[l])
		if err != nil {
			return VPCommitProof{}, err
		}
		comRLog[l] = *cLog

		c, err := curve25519.MultPointXYScalar(&vcParams.Bases[l], cLog)
		if err != nil {
			return VPCommitProof{}, err
		}
		comR[l] = *c
	}

	vpcp.ComR = comR

	// Compute the proof vcpc.DLProofR
	proof, err := DLProve(DLStatement{
		G: vcParams.Bases,
		X: vpcp.ComR,
	}, DLWitness{
		XLog: comRLog,
	})
	if err != nil {
		return VPCommitProof{}, err
	}
	vpcp.DLProofR = proof

	return vpcp, nil
}

func vpComputeComRLLog(e []curve25519.Scalar, sigmaL []curve25519.Scalar) (
	comRL *curve25519.Scalar, err error) {
	if len(e) != len(sigmaL) {
		return nil, fmt.Errorf("e and sigmaL are not the same lengths")
	}
	eMat := curve25519.NewScalarMatrixFromEntries(1, len(e), e)
	sigmaLMat := curve25519.NewScalarMatrixFromEntries(len(sigmaL), 1, sigmaL)

	comRLLogMat, err := curve25519.ScalarMatrixMul(eMat, sigmaLMat)
	if err != nil {
		return nil, err
	}

	return comRLLogMat.At(0, 0), nil
}

func vpComputeSigmaTranspose(sigma [][]curve25519.Scalar) (sigmaTranspose [][]curve25519.Scalar) {
	m := len(sigma)
	n := len(sigma[0]) - 1

	sigmaTranspose = make([][]curve25519.Scalar, n+1)
	for l := 0; l <= n; l++ {
		sigmaTranspose[l] = make([]curve25519.Scalar, m)
		for i := 0; i < m; i++ {
			sigmaTranspose[l][i] = sigma[i][l]
		}
	}

	return sigmaTranspose
}

func vpCommitAndProveComputeHashL(sigmaTranspose [][]curve25519.Scalar) (hashL [][HashLength]byte) {
	n := len(sigmaTranspose) - 1
	hashL = make([][HashLength]byte, n+1)
	for l := 0; l <= n; l++ {
		hashL[l] = VPComputeHashL(VPHashLIn{SigmaL: sigmaTranspose[l]})
	}
	return hashL
}

func VPComputeHashL(in VPHashLIn) (hashL [HashLength]byte) {
	h := sha256.New()
	h.Write([]byte("vphl")) // use a prefix for domain separation
	h.Write(msgpack.Encode(in))
	out := h.Sum(nil)

	if len(out) != HashLength {
		panic("output of sha256 not the right size")
	}
	copy(hashL[:], out)

	return hashL
}

// VPComputeHashE computes the elements e_{j,0}, ..., e_{j, m-1}
// as output of hash of the input
func VPComputeHashE(in VPHashEIn, m int) (e []curve25519.Scalar) {
	h := sha256.New()
	h.Write([]byte("vphe")) // use a prefix for domain separation
	h.Write(msgpack.Encode(in))
	out := h.Sum(nil)

	// Convert out into a scalar
	// a bit non-optimal but simplest solution with what we have
	if len(out) != curve25519.Chacha20KeyLength {
		panic("output of sha256 not the right size")
	}

	var chacha20key [curve25519.Chacha20KeyLength]byte
	copy(chacha20key[:], out)

	e = make([]curve25519.Scalar, m)
	for i := 0; i < m; i++ {
		curve25519.RandomScalarChacha20C(&e[i], (*curve25519.Chacha20Key)(&chacha20key), 0)
	}

	return e
}

// VPVerify verifies a VP proof for a
// WARNING: comC must only have the commitments of the qualified dealers
// (from Verifier j point of view)
// so it may have less than n commitments
// Warning: l is in range [0,n], which means new holding party l uses l+1
func VPVerify(vcParams feldman.VCParams, l int, comC []curve25519.PointXY,
	vpcp VPCommitProof, sigmaL []curve25519.Scalar) error {

	m := len(comC)
	if m != len(sigmaL) {
		return fmt.Errorf("comC and sigmaL have different lengths")
	}

	if len(vpcp.ComR) != len(vpcp.HashL) {
		return fmt.Errorf("different length for comR and hashL")
	}
	if len(vpcp.ComR) < l {
		return fmt.Errorf("not enough hashL/comR")
	}

	// Verify that hashL matches vpcp for l
	hashL := VPComputeHashL(VPHashLIn{
		SigmaL: sigmaL,
	})
	if hashL != vpcp.HashL[l] {
		return fmt.Errorf("invalid hashL for l=%d", l)
	}

	// Re-compute e
	e := VPComputeHashE(VPHashEIn{HashL: vpcp.HashL}, m)

	// Re-compute comRL and verify it matches vpcp for l
	comRLLog, err := vpComputeComRLLog(e, sigmaL)
	if err != nil {
		return err
	}

	comRL, err := curve25519.MultPointXYScalar(&vcParams.Bases[l], comRLLog)
	if err != nil {
		return err
	}

	if *comRL != vpcp.ComR[l] {
		return fmt.Errorf("invalid comR for l=%d", l)
	}

	// Verify vpcp.ComR have valid NIZK
	err = DLVerify(DLStatement{
		G: vcParams.Bases,
		X: vpcp.ComR,
	}, vpcp.DLProofR)
	if err != nil {
		return err
	}

	// Verify vpcp.ComR matches comC
	// that is the sum of ComR is sum e_i C_i
	sumComR, err := curve25519.AddPointsXY(vpcp.ComR)
	if err != nil {
		return err
	}
	eiCi, err := curve25519.MultiMultPointXYScalarVarTime(comC, e)
	if err != nil {
		return err
	}
	if *sumComR != *eiCi {
		return fmt.Errorf("sum of comR is not sum e_i C_i")
	}

	return nil
}
