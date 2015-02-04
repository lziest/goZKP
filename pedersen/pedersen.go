package pedersen

import (
	"crypto/sha1"
	"log"
	"math/big"

	"github.com/lziest/goZKP"
)

// PedersenProver proves the knowledge of (x, r) such that z = (g**x) * (h**r).
type PedersenProver struct {
	P *big.Int  // Zp as Group
	Q *big.Int  // G's order
	G *big.Int  // Group generator g
	H *big.Int  // Group generator h
	X *goZKP.Zr // Private x
	R *goZKP.Zr // Private r
}

type PedersenVerifier struct {
	P *big.Int // Zp as Group
	Q *big.Int // G's order
	G *big.Int // Group generator g
	H *big.Int // Group generator h
	Z *big.Int // public commitment,  z = (g**x) * (h**r)
}

func Hash(q *big.Int, values ...*big.Int) *big.Int {
	hash := sha1.New()
	for _, value := range values {
		hash.Write(value.Bytes())
	}
	h := hash.Sum(nil)
	ret := big.NewInt(0)
	ret.SetBytes(h)
	ret.Mod(ret, q)
	return ret
}

func (p *PedersenProver) Commit() ([]*big.Int, error) {
	rx, err := p.X.Commit()
	if err != nil {
		return nil, err
	}
	rr, err := p.R.Commit()
	if err != nil {
		return nil, err
	}

	g := big.NewInt(0)
	g.Exp(p.G, rx, p.P)
	log.Print("g = ", p.G.Int64())
	log.Print("g^rx = ", g.Int64())

	h := big.NewInt(0)
	h.Exp(p.H, rr, p.P)
	log.Print("h = ", p.H.Int64())
	log.Print("h^rx = ", h.Int64())

	g.Mul(g, h)
	g.Mod(g, p.P)

	ret := []*big.Int{g}
	return ret, nil
}

func (p *PedersenProver) Prove(c *big.Int) ([]*big.Int, error) {
	if c.Cmp(p.Q) > 0 {
		c.Mod(c, p.Q)
	}

	// tx = (rx - c * p.X) mod Q
	// tr = (rr - c * p.X) mod Q
	tx := p.X.Prove(c)
	tr := p.R.Prove(c)
	ret := []*big.Int{tx, tr}
	return ret, nil
}

func (p *PedersenProver) Sign(m *big.Int) ([]*big.Int, error) {
	comm, err := p.Commit()
	if err != nil {
		return nil, err
	}
	comm = append([]*big.Int{m}, comm...)
	c := Hash(p.Q, comm...)
	proof, err := p.Prove(c)
	if err != nil {
		return nil, err
	}

	proof = append(proof, c)
	return proof, nil
}

func (v *PedersenVerifier) ConsumeVerify(comm []*big.Int, c *big.Int, resp []*big.Int) (valid bool, remComm, remResp []*big.Int) {
	valid = false
	if len(resp) < 2 {
		return false, comm, resp
	}

	if len(comm) < 1 {
		return false, comm, resp
	}

	var rv *big.Int
	rv, remResp = v.RecoverCommitment(c, resp)

	rc := comm[0]
	remComm = comm[1:]

	if rv.Cmp(rc) != 0 {
		return
	}
	valid = true
	return
}

func (v *PedersenVerifier) Verify(comm []*big.Int, c *big.Int, resp []*big.Int) bool {
	valid, remComm, remResp := v.ConsumeVerify(comm, c, resp)

	if len(remComm) != 0 || len(remResp) != 0 || !valid {
		return false
	}

	return true
}

func (v *PedersenVerifier) RecoverCommitment(c *big.Int, resp []*big.Int) (rc *big.Int, remResp []*big.Int) {
	sx := resp[0]
	sr := resp[1]
	remResp = resp[2:]

	// rc = G**sx * H**sr * Z**c
	//    = G**(sx + x * c) * H**(sr + r * c)
	//    = G**rx * H**rr (mod P)
	rc = big.NewInt(0)
	rc.Exp(v.G, sx, v.P)

	tmp := big.NewInt(0)
	tmp.Exp(v.H, sr, v.P)
	rc.Mul(rc, tmp)
	rc.Mod(rc, v.P)

	tmp.Exp(v.Z, c, v.P)
	rc.Mul(rc, tmp)
	rc.Mod(rc, v.P)

	return rc, remResp
}

func (v *PedersenVerifier) VerifySig(m *big.Int, resp []*big.Int) bool {
	if len(resp) != 3 {
		return false
	}
	remResp := resp[:len(resp)-1]
	chlg := resp[len(resp)-1]

	rv, remResp := v.RecoverCommitment(chlg, remResp)

	if len(remResp) != 0 {
		return false
	}

	// c = H(M, rv)
	c := Hash(v.Q, m, rv)
	if c.Cmp(chlg) != 0 {
		return false
	}
	return true

}
