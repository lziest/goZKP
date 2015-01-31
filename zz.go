package goZKP

import (
	"errors"
	"math/big"
)

// ZZ represents a multipicative group of Z_p.
type ZZ struct {
	g      *big.Int
	modulo *big.Int
}

func (z *ZZ) Bytes() []byte {
	return z.g.Bytes()
}

func (z *ZZ) Mul(x *ZZ) (*ZZ, error) {
	if x.modulo.Cmp(z.modulo) != 0 {
		return nil, errors.New("Unmatched modulo in ZZ multiplication.")
	}
	z.g.Mul(z.g, x.g)
	z.g.Mod(z.g, z.modulo)
	return z, nil
}

func (z *ZZ) Exp(x *big.Int) *ZZ {
	z.g.Exp(z.g, x, z.modulo)
	return z
}

func (z *ZZ) Inverse() *ZZ {
	z.g.ModInverse(z.g, z.modulo)
	return z
}
