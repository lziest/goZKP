package pedersen

import (
	"crypto/sha1"
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
