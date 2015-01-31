package goZKP

import (
	"crypto/rand"
	"errors"
	"log"
	"math/big"
)

var ZERO = big.NewInt(0)

// Zr represents the group of exponents for some multiplicative group.
// Zr is a base units of ZKP, and is associated with a random
// value as a commitment.
type Zr struct {
	Value  *big.Int // the actual value of Zr
	Modulo *big.Int // the order of Zr
	r      *big.Int // the corresponding random commitment.
}

func (z *Zr) Bytes() []byte {
	return z.Value.Bytes()
}

func (z *Zr) Mul(x *Zr) (*Zr, error) {
	if x.Modulo.Cmp(z.Modulo) != 0 {
		return nil, errors.New("Unmatched Modulo in Zr multiplication.")
	}
	z.Value.Mul(z.Value, x.Value)
	z.Value.Mod(z.Value, z.Modulo)
	return z, nil
}

func (z *Zr) Exp(x *big.Int) *Zr {
	z.Value.Exp(z.Value, x, z.Modulo)
	return z
}

func (z *Zr) Inverse() *Zr {
	z.Value.ModInverse(z.Value, z.Modulo)
	return z
}

func (z *Zr) Commit() (*big.Int, error) {
	if z.r == nil {
		var err error
		z.r, err = rand.Int(rand.Reader, z.Modulo)
		if err != nil {
			return nil, err
		}
		return z.r, nil
	}

	// if it already committed a random number, return it
	return z.r, nil
}

func (z *Zr) Prove(c *big.Int) *big.Int {
	if c.Cmp(z.Modulo) > 0 {
		c.Mod(c, z.Modulo)
	}

	log.Print("c = ", c.Int64())
	tmp := big.NewInt(0)
	tmp.Mul(c, z.Value)
	tmp.Mod(tmp, z.Modulo)
	tmp.Sub(z.r, tmp)
	tmp.Mod(tmp, z.Modulo)
	return tmp
}
