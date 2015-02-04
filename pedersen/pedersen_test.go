package pedersen

import (
	"math/big"
	"testing"

	"github.com/lziest/goZKP"
)

func TestProverVerifierSanity(t *testing.T) {
	p := big.NewInt(127)
	q := big.NewInt(7)
	g := big.NewInt(2)
	h := big.NewInt(4)
	x := &goZKP.Zr{Value: big.NewInt(3), Modulo: q}
	r := &goZKP.Zr{Value: big.NewInt(4), Modulo: q}
	pub := big.NewInt(16)
	prover := &PedersenProver{P: p, G: g, Q: q, H: h, X: x, R: r}
	verifier := &PedersenVerifier{P: p, G: g, Q: q, H: h, Z: pub}

	comm, _ := prover.Commit()
	var i int64
	for i = 1; i < 7; i++ {
		c := big.NewInt(i)
		resp, _ := prover.Prove(c)
		res := verifier.Verify(comm, c, resp)
		if res != true {
			t.Fatal("Failed to verify minimal test.")
		}
	}
}

func TestZKPSanity(t *testing.T) {
	p := big.NewInt(127)
	q := big.NewInt(7)
	g := big.NewInt(2)
	h := big.NewInt(4)
	x := &goZKP.Zr{Value: big.NewInt(3), Modulo: q}
	r := &goZKP.Zr{Value: big.NewInt(4), Modulo: q}
	pub := big.NewInt(16)
	prover := &PedersenProver{P: p, G: g, Q: q, H: h, X: x, R: r}
	verifier := &PedersenVerifier{P: p, G: g, Q: q, H: h, Z: pub}

	var i int64
	for i = 1; i < 7; i++ {
		m := big.NewInt(i)
		proof, err := prover.Sign(m)
		if err != nil {
			t.Fatal("Failed to sign")
		}
		res := verifier.VerifySig(m, proof)
		if res != true {
			t.Fatal("Failed to verify minimal ZKP test.")
		}
	}
}
