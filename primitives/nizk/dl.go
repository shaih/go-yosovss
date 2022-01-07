package nizk

import (
	"crypto/sha256"
	"fmt"

	"github.com/shaih/go-yosovss/msgpack"
	"github.com/shaih/go-yosovss/primitives/curve25519"
)

// This file is to handle NIZK Proof of Knowledge of discrete logarithms
// Concretely the statement is (G_0,...,G_{n-1},X_0, ..., X_{n-1})
// and the prover shows knowledge of x_0,...,x_{n-1} such that
// for all i: X_i = x_i G_i

// WARNING: Actually the proof is only modulo p
//    X_i may have extraneous factors modulo the co-factor
//    and this may not be caught

// Verification is batched for efficiency for large n
// Smaller n may be less efficient

// The proof works as follows:
// generate random scalars comLog[0],...,comLog[n-1]
// and associated points com[i] = comLog[i] * G[i]
// combine those into an input hash (see DLChHashIn below)
// hash it to get a challenge scalar Ch
// set resp[i] = comLog[i] + ch * x_i

// DLStatement describes a statement, see comment top of file
type DLStatement struct {
	G []curve25519.PointXY `codec:"G"`
	X []curve25519.PointXY `codec:"X"`
}

// DLWitness describes a witness for a statement
type DLWitness struct {
	XLog []curve25519.Scalar `codec:"x"` // XLog[i] = x_i = discrete logarithm of X[i] in base G[i]
}

// DLChHashIn is the input to the hash function used to compute the challenge
type DLChHashIn struct {
	Stmt DLStatement          `codec:"s"`
	Com  []curve25519.PointXY `codec:"c"`
}

// DLProof is an actual proof
// For batching the proof contain com and resp instead of ch and resp
// which is more compact but not possible to batch
type DLProof struct {
	Com  []curve25519.PointXY // Com is the commtiments
	Resp []curve25519.Scalar  // Resp
}

func dlBasicCheckStatement(stmt DLStatement) error {
	if len(stmt.X) != len(stmt.G) {
		return fmt.Errorf("G and X do not have the same length")
	}

	if len(stmt.X) == 0 {
		return fmt.Errorf("G/X is empty")
	}

	return nil
}

// dlProveGenCom generates the commitments DL and the commitments for the NIZK proof
func dlProveGenCom(stmt DLStatement) (comLog []curve25519.Scalar, com []curve25519.PointXY, err error) {
	n := len(stmt.G)

	chacha20Key, err := curve25519.RandomChacha20Key()
	if err != nil {
		return nil, nil, err
	}

	comLog = make([]curve25519.Scalar, n)
	com = make([]curve25519.PointXY, n)

	for i := 0; i < n; i++ {
		// generate comLog[i] randomly using the Chacha generator
		curve25519.RandomScalarChacha20C(&comLog[i], &chacha20Key, uint64(i))

		// compute com[i] = comLog[i] * G[i]
		c, err := curve25519.MultPointXYScalar(&stmt.G[i], &comLog[i])
		if err != nil {
			return nil, nil, err
		}
		com[i] = *c
	}

	return comLog, com, err
}

// dlProveResp computes the response to a challenge in the sigma protocol for the NIZK
func dlProveResp(wit DLWitness, comLog []curve25519.Scalar, chal *curve25519.Scalar) (resp []curve25519.Scalar) {
	n := len(wit.XLog)
	resp = make([]curve25519.Scalar, n)

	for i := 0; i < n; i++ {
		// resp[i] = comLog[i] + chal * XLog[i]
		ri := curve25519.MultScalar(chal, &wit.XLog[i])
		ri = curve25519.AddScalar(ri, &comLog[i])
		resp[i] = *ri
	}

	return resp
}

// DLProve generates a NIZK PoK for the statement stmt using witness wit
// Does not verify the validity of the witness
func DLProve(stmt DLStatement, wit DLWitness) (DLProof, error) {
	err := dlBasicCheckStatement(stmt)
	if err != nil {
		return DLProof{}, err
	}

	comLog, com, err := dlProveGenCom(stmt)
	if err != nil {
		return DLProof{}, err
	}

	dchi := DLChHashIn{
		Stmt: stmt,
		Com:  com,
	}

	chal := DLChHash(dchi)

	resp := dlProveResp(wit, comLog, &chal)

	proof := DLProof{
		Com:  com,
		Resp: resp,
	}

	return proof, nil
}

func DLVerify(stmt DLStatement, proof DLProof) error {
	err := dlBasicCheckStatement(stmt)
	if err != nil {
		return err
	}

	n := len(stmt.X)

	dchi := DLChHashIn{
		Stmt: stmt,
		Com:  proof.Com,
	}
	chal := DLChHash(dchi)

	// TODO: optimization is having these values 128 bits long instead

	// generate batching values e[0],...,e[n-1]
	// randomly
	chacha20key, err := curve25519.RandomChacha20Key()
	if err != nil {
		panic("error generating chacha20 key")
	}

	e := make([]curve25519.Scalar, n)
	for i := 0; i < n; i++ {
		curve25519.RandomScalarChacha20C(&e[i], &chacha20key, uint64(i))
	}

	// pts contain [G[0],...,G[n-1], X[0],...,X[n-1], com[0],...,com[n-1]]
	pts := []curve25519.PointXY{}
	pts = append(pts, stmt.G...)
	pts = append(pts, stmt.X...)
	pts = append(pts, proof.Com...)

	// check pts are all on the curve (except the base points that are necessarily there)
	for i := n; i < len(pts); i++ {
		if !curve25519.IsOnCurveXY(&pts[i]) {
			return fmt.Errorf("pts[%d] is not on the curve", i)
		}
	}

	// scalars contain [-e[0] * resp[0], ..., -e[n-1] * resp[n-1], e[0] * chal, ..., e[n-1] * chal, e[0], ..., e[n-1]]
	scalars := make([]curve25519.Scalar, 3*n)
	for i := 0; i < n; i++ {
		scalars[i] = *curve25519.NegateScalar(curve25519.MultScalar(&e[i], &proof.Resp[i]))
	}
	for i := 0; i < n; i++ {
		scalars[n+i] = *curve25519.MultScalar(&e[i], &chal)
	}
	for i := 0; i < n; i++ {
		scalars[2*n+i] = e[i]
	}

	// Final verification of the equation
	// pts scalar product with scalars is the point at infinitiy
	r, err := curve25519.MultiMultPointXYScalarVarTime(pts, scalars)
	if err != nil {
		return err
	}

	if !curve25519.PointXYEqual(r, &curve25519.PointXYInfinity) {
		return fmt.Errorf("batch verification equation failed")
	}

	return nil
}

func DLChHash(dchi DLChHashIn) (chal curve25519.Scalar) {
	h := sha256.New()
	h.Write([]byte("dlpok")) // use a prefix for domain separation
	h.Write(msgpack.Encode(dchi))
	out := h.Sum(nil)

	// Convert out into a scalar
	// a bit non-optimal but simplest solution with what we have
	if len(out) != curve25519.Chacha20KeyLength {
		panic("output of sha256 not the right size")
	}

	var chacha20key [curve25519.Chacha20KeyLength]byte
	copy(chacha20key[:], out)
	curve25519.RandomScalarChacha20C(&chal, (*curve25519.Chacha20Key)(&chacha20key), 0)

	return chal
}
