package goZKP

import (
	"math/big"
)

type Prover interface {
	Commit() ([]*big.Int, error)
	Prove(c *big.Int) ([]*big.Int, error)
}

type ZKPSigner interface {
	Prover
	Sign(m *big.Int) ([]*big.Int, error)
}

type Verifier interface {
	Verify(comm []*big.Int, c *big.Int, resp []*big.Int) (remComm, remResp []*big.Int, valid bool)
}

type ZKPVerifier interface {
	VerifySig(m *big.Int, sig []*big.Int) ([]*big.Int, error)
}
