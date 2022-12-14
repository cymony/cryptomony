// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package opaque

import (
	"github.com/cymony/cryptomony/eccgroup"
	"github.com/cymony/cryptomony/oprf"
)

func (os *opaqueSuite) deterministicBlind(password []byte, blind *eccgroup.Scalar) (*eccgroup.Scalar, *eccgroup.Element, error) {
	oprfCl, err := oprf.NewClient(os.OPRF())
	if err != nil {
		return nil, nil, err
	}

	inputs := [][]byte{password}
	blinds := []*eccgroup.Scalar{blind}

	findData, evalReq, err := oprfCl.DeterministicBlind(inputs, blinds)
	if err != nil {
		return nil, nil, err
	}

	if len(evalReq.BlindedElements) != 1 {
		return nil, nil, ErrOPRFBlind
	}

	if len(findData.Blinds) != 1 {
		return nil, nil, ErrOPRFBlind
	}

	blindedEl := evalReq.BlindedElements[0]

	blindSc := findData.Blinds[0]

	return blindSc, blindedEl, nil
}

func (os *opaqueSuite) finalize(evaluatedEl *eccgroup.Element, password []byte, blind *eccgroup.Scalar) ([]byte, error) {
	oprfCl, err := oprf.NewClient(os.OPRF())
	if err != nil {
		return nil, err
	}

	evalRes := &oprf.EvaluationResponse{
		EvaluatedElements: []*eccgroup.Element{evaluatedEl},
	}

	finData := &oprf.FinalizeData{
		Inputs:      [][]byte{password},
		Blinds:      []*eccgroup.Scalar{blind},
		EvalRequest: &oprf.EvaluationRequest{},
	}

	finOut, err := oprfCl.Finalize(finData, evalRes)
	if err != nil {
		return nil, err
	}

	if len(finOut) != 1 {
		return nil, ErrOPRFFinalize
	}

	return finOut[0], nil
}

func (os *opaqueSuite) evaluate(blindedEl *eccgroup.Element, oprfKey *PrivateKey) (*eccgroup.Element, error) {
	evalReq := &oprf.EvaluationRequest{
		BlindedElements: []*eccgroup.Element{blindedEl},
	}

	sw, err := oprf.NewServer(os.OPRF(), oprfKey.privKey)
	if err != nil {
		return nil, err
	}

	evalRes, err := sw.BlindEvaluate(evalReq)
	if err != nil {
		return nil, err
	}

	if len(evalRes.EvaluatedElements) != 1 {
		return nil, ErrOPRFEvaluate
	}

	return evalRes.EvaluatedElements[0], nil
}
