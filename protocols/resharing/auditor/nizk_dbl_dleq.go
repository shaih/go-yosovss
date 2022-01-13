package auditor

import (
	"fmt"

	"github.com/shaih/go-yosovss/primitives/curve25519"
)

// This file should be in a package nizk in primitives
// but because of weird issues with codecgen, having
// two codecgen seems to create too many problems
// So to dirtily fix things, we move this file here even if not ideal

// This file is to handle NIZK Proof of Knowledge of discrete logarithms
// Concretely the statement is
// (G_0,...,G_{n-1},H_0,...,H_{n-1},Z_0,...,Z_{n-1},Z'_0,...,Z'_{n-1})
// and the prover shows knowledge of x_0,...,x_{n-1}, y_0,...,y_{n-1} such that
// for all i:
//   Z_i = x_i G + y_i H (G,H are the two main basis)
//   Z'_i = x_i' G_i + y_i' H_i

// WARNING: Actually the proof is only modulo p
//    X_i may have extraneous factors modulo the co-factor
//    and this may not be caught

// Verification is batched for efficiency for large n
// Smaller n may be less efficient

// The proof works as follows:
// generate random scalars comGLog[0],...,comGLog[n-1],comHLog[0],...,comHLog[n-1]
// and associated points
//    com[i] = comGLog[i] * G + comHLog[i] * H
//    comPrime[i] = comGLog[i] * G[i] + comHLog[i] * H[i]
// combine those into an input hash (see DLChHashIn below)
// hash it to get a challenge scalar Ch
// set
//    respG[i] = comGLog[i] + ch * x_i
//    respH[i] = comGLog[i] + ch * x_i

// DblDLEqStatement describes a statement, see comment top of file
type DblDLEqStatement struct {
	G      []curve25519.PointXY `codec:"G"`
	H      []curve25519.PointXY `codec:"H"`
	Z      []curve25519.PointXY `codec:"Z"`
	ZPrime []curve25519.PointXY `codec:"Z"`
}

type DblDLEqWitness struct {
	X []curve25519.Scalar `codec:"x"`
	Y []curve25519.Scalar `codec:"y"`
}

type DblDLEqHashIn struct {
	Stmt     DblDLEqStatement     `codec:"s"`
	Com      []curve25519.PointXY `codec:"g"`
	ComPrime []curve25519.PointXY `codec:"h"`
}

type DblDLEqProof struct {
	Com      []curve25519.PointXY `codec:"g"`
	ComPrime []curve25519.PointXY `codec:"h"`
	RespG    []curve25519.Scalar  `codec:"G"`
	RespH    []curve25519.Scalar  `codec:"H"`
}

func dblDLEqBasicCheckStatement(stmt DblDLEqStatement) error {
	if len(stmt.G) != len(stmt.H) {
		return fmt.Errorf("G and H do not have the same length")
	}
	if len(stmt.G) != len(stmt.Z) {
		return fmt.Errorf("G and Z do not have the same length")
	}
	if len(stmt.G) != len(stmt.ZPrime) {
		return fmt.Errorf("G and ZPrime do not have the same length")
	}

	if len(stmt.G) == 0 {
		return fmt.Errorf("G is empty")
	}

	return nil
}

// dblDLEqProveGenCom generates the commitments DL and the commitments for the NIZK proof
func dblDLEqProveGenCom(stmt DblDLEqStatement) (
	comGLog []curve25519.Scalar, comHLog []curve25519.Scalar,
	com []curve25519.PointXY, comPrime []curve25519.PointXY,
	err error) {

	n := len(stmt.G)

	chacha20Key, err := curve25519.RandomChacha20Key()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	comGLog = make([]curve25519.Scalar, n)
	comHLog = make([]curve25519.Scalar, n)

	com = make([]curve25519.PointXY, n)
	comPrime = make([]curve25519.PointXY, n)

	for i := 0; i < n; i++ {
		// generate comGLog[i]/comHLog[i] randomly using the Chacha generator
		curve25519.RandomScalarChacha20C(&comGLog[i], &chacha20Key, uint64(i))
		curve25519.RandomScalarChacha20C(&comHLog[i], &chacha20Key, uint64(i+n))

		// compute com[i] = comGLog[i] * G + comHLog[i] * H
		c, err := curve25519.DoubleMultBaseGHPointXYScalar(&comGLog[i], &comHLog[i])
		if err != nil {
			return nil, nil, nil, nil, err
		}
		com[i] = *c

		// compute com[i] = comGLog[i] * G[i] + comHLog[i] * H[i]
		c, err = curve25519.MultiMultPointXYScalar(
			[]curve25519.PointXY{stmt.G[i], stmt.H[i]},
			[]curve25519.Scalar{comGLog[i], comHLog[i]},
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		comPrime[i] = *c
	}

	return comGLog, comHLog, com, comPrime, err
}

// dblDLEqProveResp computes the response to a challenge in the sigma protocol for the NIZK
func dblDLEqProveResp(wit DblDLEqWitness,
	comGLog []curve25519.Scalar, comHLog []curve25519.Scalar,
	chal *curve25519.Scalar) (respG []curve25519.Scalar, respH []curve25519.Scalar) {

	n := len(wit.X)
	respG = make([]curve25519.Scalar, n)
	respH = make([]curve25519.Scalar, n)

	for i := 0; i < n; i++ {
		// respG[i] = comGLog[i] + chal * X[i]
		ri := curve25519.MultScalar(chal, &wit.X[i])
		ri = curve25519.AddScalar(ri, &comGLog[i])
		respG[i] = *ri

		// respH[i] = comHLog[i] + chal * Y[i]
		ri = curve25519.MultScalar(chal, &wit.Y[i])
		ri = curve25519.AddScalar(ri, &comHLog[i])
		respH[i] = *ri
	}

	return respG, respH
}

// DblDLEqProve generates a NIZK PoK for the statement stmt using witness wit
// Does not verify the validity of the witness
func DblDLEqProve(stmt DblDLEqStatement, wit DblDLEqWitness) (DblDLEqProof, error) {
	err := dblDLEqBasicCheckStatement(stmt)
	if err != nil {
		return DblDLEqProof{}, err
	}

	comGLog, comHLog, com, comPrime, err := dblDLEqProveGenCom(stmt)
	if err != nil {
		return DblDLEqProof{}, err
	}

	hin := DblDLEqHashIn{
		Stmt:     stmt,
		Com:      com,
		ComPrime: comPrime,
	}

	chal := DblDLEqChHash(hin)

	respG, respH := dblDLEqProveResp(wit, comGLog, comHLog, &chal)

	proof := DblDLEqProof{
		Com:      com,
		ComPrime: comPrime,
		RespG:    respG,
		RespH:    respH,
	}

	return proof, nil
}

func DblDLEqVerify(stmt DblDLEqStatement, proof DblDLEqProof) error {
	err := dblDLEqBasicCheckStatement(stmt)
	if err != nil {
		return err
	}

	n := len(stmt.G)

	hin := DblDLEqHashIn{
		Stmt:     stmt,
		Com:      proof.Com,
		ComPrime: proof.ComPrime,
	}
	chal := DblDLEqChHash(hin)

	// TODO: optimization is having these values 128 bits long instead

	// generate batching values e[0],...,e[n-1]
	// randomly
	chacha20key, err := curve25519.RandomChacha20Key()
	if err != nil {
		panic("error generating chacha20 key")
	}

	e := make([]curve25519.Scalar, 2*n)
	for i := 0; i < 2*n; i++ {
		curve25519.RandomScalarChacha20C(&e[i], &chacha20key, uint64(i))
	}

	// pts contain
	// [
	//   G,
	//   H,
	//   G[0],...,G[n-1],
	//   H[0],...,H[n-1],
	//   Z[0],...,Z[n-1],
	//   ZPrime[0],...,ZPrime[n-1]
	//   Com[0],...,Com[n-1],
	//   ComPrime[0],...,ComPrime[n-1],
	// ]
	pts := make([]curve25519.PointXY, 0, 2+6*n)
	pts = append(pts, curve25519.BaseXYG, curve25519.BaseXYH)
	pts = append(pts, stmt.G...)
	pts = append(pts, stmt.H...)
	pts = append(pts, stmt.Z...)
	pts = append(pts, stmt.ZPrime...)
	pts = append(pts, proof.Com...)
	pts = append(pts, proof.ComPrime...)

	// check pts are all on the curve (except the base points that are necessarily there)
	for i := n + 2; i < len(pts); i++ {
		if !curve25519.IsOnCurveXY(&pts[i]) {
			return fmt.Errorf("pts[%d] is not on the curve", i)
		}
	}

	// scalars contain
	// [
	//   sum_i -e[i] * respG[i]
	//   sum_i -e[i] * respH[i]
	//   -e[n] * respG[0], ..., -e[2n-1] * respG[n-1],
	//   -e[n] * respH[0], ..., -e[2n-1] * respH[n-1],
	//   e[0] * chal, ..., e[n-1] * chal,
	//   e[n] * chal, ..., e[2n-1] * chal,
	//   e[0], ..., e[n-1],
	//   e[n], ..., e[2n-1]
	// ]
	scalars := make([]curve25519.Scalar, 2+6*n)

	// scalars[0] = sum_i -e[i] * respG[i]
	eGVec := curve25519.NewScalarMatrixFromEntries(1, n, e[:n])
	respGVec := curve25519.NewScalarMatrixFromEntries(n, 1, proof.RespG)
	s0, err := curve25519.ScalarMatrixMul(eGVec, respGVec)
	if err != nil {
		return err
	}
	scalars[0] = *curve25519.NegateScalar(s0.At(0, 0))

	// scalars[1] = sum_i -e[i+n] * respH[i]
	eHVec := curve25519.NewScalarMatrixFromEntries(1, n, e[:n])
	respHVec := curve25519.NewScalarMatrixFromEntries(n, 1, proof.RespH)
	s1, err := curve25519.ScalarMatrixMul(eHVec, respHVec)
	if err != nil {
		return err
	}
	scalars[1] = *curve25519.NegateScalar(s1.At(0, 0))

	// scalars[2:]
	for i := 0; i < n; i++ {
		scalars[2+i] = *curve25519.NegateScalar(curve25519.MultScalar(&e[i+n], &proof.RespG[i]))
	}
	for i := 0; i < n; i++ {
		scalars[n+2+i] = *curve25519.NegateScalar(curve25519.MultScalar(&e[i+n], &proof.RespH[i]))
	}
	for i := 0; i < 2*n; i++ {
		scalars[2*n+2+i] = *curve25519.MultScalar(&e[i], &chal)
	}
	for i := 0; i < 2*n; i++ {
		scalars[4*n+2+i] = e[i]
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

func DblDLEqChHash(in DblDLEqHashIn) (chal curve25519.Scalar) {
	return zkHash("dbl_dleq", in)
}
