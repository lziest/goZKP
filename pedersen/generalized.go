package pedersen

import (
	"log"
	"math/big"

	"github.com/lziest/goZKP"
)

// GeneralizedPedersenProver proves the knowledge of ({x_1, .. x_n}, r)
// such that z = \Pi(g_i**x_i) * (h**r).
type GeneralizedPedersenProver struct {
	P         *big.Int    // Zp as Group
	Q         *big.Int    // G's order
	Bases     []*big.Int  // Group generators {g_i}
	H         *big.Int    // Group generator h
	Exponents []*goZKP.Zr // Private {x_i}
	R         *goZKP.Zr   // Private r
}

type GeneralizedPedersenVerifier struct {
	P     *big.Int   // Zp as Group
	Q     *big.Int   // G's order
	Bases []*big.Int // Group generators {g_i}
	H     *big.Int   // Group generator h
	Z     *big.Int   // public commitment,  z = (g**x) * (h**r)
}

func (p *GeneralizedPedersenProver) Commit() ([]*big.Int, error) {
	rlist := []*big.Int{}
	for _, x := range p.Exponents {
		rx, err := x.Commit()
		rlist = append(rlist, rx)
		if err != nil {
			return nil, err
		}
	}

	rr, err := p.R.Commit()
	if err != nil {
		return nil, err
	}

	product := big.NewInt(1)
	g := big.NewInt(0)
	for i, rx := range rlist {
		g.Exp(p.Bases[i], rx, p.P)
		product.Mul(g, product)
		product.Mod(product, p.P)
		log.Print("g = ", p.Bases[i].Int64())
		log.Print("g^rx = ", g.Int64())
	}

	h := big.NewInt(0)
	h.Exp(p.H, rr, p.P)
	log.Print("h = ", p.H.Int64())
	log.Print("h^rr = ", h.Int64())

	product.Mul(product, h)
	product.Mod(product, p.P)

	ret := []*big.Int{product}
	return ret, nil
}

func (p *GeneralizedPedersenProver) Prove(c *big.Int) ([]*big.Int, error) {
	if c.Cmp(p.Q) > 0 {
		c.Mod(c, p.Q)
	}

	ret := []*big.Int{}
	for _, x := range p.Exponents {
		tx := x.Prove(c)
		ret = append(ret, tx)
	}
	tr := p.R.Prove(c)
	ret = append(ret, tr)

	return ret, nil
}

func (p *GeneralizedPedersenProver) Sign(m *big.Int) ([]*big.Int, error) {
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

func (v *GeneralizedPedersenVerifier) ConsumeVerify(comm []*big.Int, c *big.Int, resp []*big.Int) (valid bool, remComm, remResp []*big.Int) {
	valid = false
	if len(resp) < len(v.Bases) {
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

func (v *GeneralizedPedersenVerifier) Verify(comm []*big.Int, c *big.Int, resp []*big.Int) bool {
	valid, remComm, remResp := v.ConsumeVerify(comm, c, resp)

	if len(remComm) != 0 || len(remResp) != 0 || !valid {
		return false
	}

	return true
}

func (v *GeneralizedPedersenVerifier) RecoverCommitment(c *big.Int, resp []*big.Int) (rc *big.Int, remResp []*big.Int) {

	rc = big.NewInt(1)

	tmp := big.NewInt(0)
	for i, base := range v.Bases {
		tmp.Exp(base, resp[i], v.P)
		rc.Mul(rc, tmp)
		rc.Mod(rc, v.P)
	}

	sr := resp[len(v.Bases)]
	tmp.Exp(v.H, sr, v.P)
	rc.Mul(rc, tmp)
	rc.Mod(rc, v.P)

	remResp = resp[len(v.Bases)+1:]

	return rc, remResp
}

func (v *GeneralizedPedersenVerifier) VerifySig(m *big.Int, resp []*big.Int) bool {
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
