package schnoor

import (
	"crypto/rand"
	"crypto/sha1"
	"log"
	"math/big"
)

type SchnorrProver struct {
	P    *big.Int // Zp as Group
	G    *big.Int // Group generator g
	Q    *big.Int // G's order
	Priv *big.Int // private key
	r    *big.Int // random value for commitment
}

type SchnorrVerifier struct {
	P   *big.Int // Zp as Group
	G   *big.Int // Group generator
	Q   *big.Int // G's order
	Pub *big.Int // public key,  G**Priv
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

func (p *SchnorrProver) Commit() ([]*big.Int, error) {
	r, err := rand.Int(rand.Reader, p.Q)
	if err != nil {
		return nil, err
	}
	log.Print("r = ", r.Int64())
	p.r = r
	g := big.NewInt(0)
	g.Exp(p.G, r, p.P)
	log.Print("g = ", p.G.Int64())
	log.Print("g^r = ", g.Int64())
	ret := []*big.Int{g}
	return ret, nil
}

func (p *SchnorrProver) Prove(c *big.Int) ([]*big.Int, error) {
	// tmp = (r - c * p.Priv) mod Q
	log.Print("c = ", c.Int64())
	tmp := big.NewInt(0)
	tmp.Mul(c, p.Priv)
	tmp.Mod(tmp, p.Q)
	tmp.Sub(p.r, tmp)
	tmp.Mod(tmp, p.Q)
	ret := []*big.Int{tmp}
	log.Print("resp = ", tmp.Int64())
	return ret, nil
}

func (p *SchnorrProver) Sign(m *big.Int) ([]*big.Int, error) {
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

func (v *SchnorrVerifier) Verify(comm []*big.Int, c *big.Int, resp []*big.Int) bool {
	if len(resp) != 1 {
		return false
	}
	s := resp[0]
	if len(comm) != 1 {
		return false
	}
	rc := comm[0]
	// Could be improved by multi-base exp.
	// r_v = G**s * Pub**c = G**(s + Priv * c) = g**r (mod P)
	rv := big.NewInt(0)
	rv.Exp(v.G, s, v.P)
	tmp := big.NewInt(0)
	tmp.Exp(v.Pub, c, v.P)

	rv.Mul(rv, tmp)
	rv.Mod(rv, v.P)

	if rv.Cmp(rc) != 0 {
		return false
	}
	return true
}

func (v *SchnorrVerifier) VerifySig(m *big.Int, resp []*big.Int) bool {
	if len(resp) != 2 {
		return false
	}
	s := resp[0]
	e := resp[1]

	// Could be improved by multi-base exp.
	// r_v = G**s * Pub**c = G**(s + Priv * c) = g**r (mod P)
	rv := big.NewInt(0)
	rv.Exp(v.G, s, v.P)
	tmp := big.NewInt(0)
	tmp.Exp(v.Pub, e, v.P)

	rv.Mul(rv, tmp)
	rv.Mod(rv, v.P)

	// c = H(M, rv)
	c := Hash(v.Q, m, rv)
	if c.Cmp(e) != 0 {
		return false
	}
	return true

}

func RandMessage() *big.Int {
	max := big.NewInt(160)
	n, _ := rand.Int(rand.Reader, max)
	return n
}
