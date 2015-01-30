package goZKP

import (
	"crypto/rand"
	"errors"
	"math/big"
)

var ZERO = big.NewInt(0)

// Zr represents the group of exponents for some multiplicative group.
// Zr is a base units of ZKP, and is associated with a random
// value as a commitment.
type Zr struct {
	Value  *big.Int // the actual value of Zr
	modulo *big.Int // the order of Zr
	r      *big.Int // the corresponding random commitment.
}

func (z *Zr) Bytes() []byte {
	return z.Value.Bytes()
}

func (z *Zr) Mul(x *Zr) (*Zr, error) {
	if x.modulo.Cmp(z.modulo) != 0 {
		return nil, errors.New("Unmatched modulo in Zr multiplication.")
	}
	z.Value.Mul(z.Value, x.g)
	z.Value.Mod(z.Value, z.modulo)
	return z, nil
}

func (z *Zr) Exp(x *big.Int) *Zr {
	z.Value.Exp(z.Value, x, z.modulo)
	return x
}

func (z *Zr) Inverse() *Zr {
	z.Value.ModInverse(z.Value, z.modulo)
	return z
}

func (z *Zr) Commit() (*big.Int, error) {
	if z.r == nil {
		var err error
		z.r, err = rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		return z.r, nil
	}

	return z.r
}

func (z *Zr) Prove(c *big.Int) *big.Int {
	if c.Cmp(z.modulo) > 0 {
		c.Mod(c, z.modulo)
	}

	log.Print("c = ", c.Int64())
	tmp := big.NewInt(0)
	tmp.Mul(c, z.Value)
	tmp.Mod(tmp, z.modulo)
	tmp.Sub(z.r, tmp)
	tmp.Mod(tmp, z.modulo)
	return tmp
}
