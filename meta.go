package goZKP

import (
	"math/big"
)

type MetaProver struct {
	subprovers []Prover
}

type MetaVerifier struct {
	subverifiers []Verifier
}

func (p *MetaProver) Commit() ([]*big.Int, error) {
	ret := []*big.Int{}
	for _, prover := range p.subprovers {
		c, err := prover.Commit()
		if err != nil {
			return nil, err
		}
		ret = append(ret, c...)
	}
	return ret, nil
}

// subprover should be aware of shared private variables so their
// commitments on shared private variables are consistent/same.
func (p *MetaProver) Prove(c *big.Int) ([]*big.Int, error) {
	ret := []*big.Int{}
	for _, prover := range p.subprovers {
		p, err := prover.Prove(c)
		if err != nil {
			return nil, err
		}
		ret = append(ret, p...)
	}
	return ret, nil
}

func (v *MetaVerifier) Verify(comm []*big.Int, c *big.Int, resp []*big.Int) bool {
	remComm := comm
	remResp := resp
	isValid := true
	for _, verifier := range v.subverifiers {
		isValid, remComm, remResp = verifier.ConsumeVerify(remComm, c, remResp)
		if !isValid {
			return false
		}
	}
	return isValid
}

// An example of MetaSigner will have a method as follows:
//
//func (p *MetaProver) Sign(m *big.Int) ([]*big.Int, error) {
//	comm, err := p.Commit()
//	if err != nil {
//		return nil, err
//	}
//	comm = append([]*big.Int{m}, comm...)
//	c := Hash(comm)
//	proof, err := p.Prove(c)
//	if err != nil {
//		return nil, err
//	}
//
//	proof = append(proof, c)
//	return proof, nil
//}
