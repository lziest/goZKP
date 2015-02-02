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
	// Verify would verify commitments against the challenge value
	// and prover's response values.
	Verify(comm []*big.Int, chlg *big.Int, resp []*big.Int) bool
	// To enable aggregated response
	// verification, i.e. multiple provers proving the knowledge of
	// their commitments at the same time via one challenge, ConsumeVerify
	// will only consume comm and resp as a stream and will return
	// remaining commiments and remaining response as remComm and
	// remResp respectively.
	ConsumeVerify(comm []*big.Int, chlg *big.Int, resp []*big.Int) (valid bool, remComm, remResp []*big.Int)
}

type ZKPVerifier interface {
	// RecoverCommitment computes the commitment in theory that
	// should be identical to the hidden commitment used by
	// ZKPSigner.
	// To enable aggragated proof verification, this is designed
	// as stream consumer that only consumes necessary response
	// values in a signature.
	RecoverCommitment(chlg *big.Int, resp []*big.Int) (rc *big.Int, remResp []*big.Int)
	// VerifySig verifies a ZKP signature.
	VerifySig(m *big.Int, sig []*big.Int) bool
}
