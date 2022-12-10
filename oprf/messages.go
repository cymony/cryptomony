// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package oprf

import (
	"github.com/cymony/cryptomony/dleq"
	"github.com/cymony/cryptomony/eccgroup"
)

type EvaluationRequest struct {
	BlindedElements []*eccgroup.Element
}

type EvaluationResponse struct {
	Proof             dleq.Proof
	EvaluatedElements []*eccgroup.Element
}

type FinalizeData struct {
	EvalRequest *EvaluationRequest
	Inputs      [][]byte
	Blinds      []*eccgroup.Scalar
}
