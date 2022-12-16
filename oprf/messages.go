// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oprf

import (
	"github.com/cymony/cryptomony/eccgroup"
)

// EvaluationRequest identify the message send from client to server
// for Evaluation operation
type EvaluationRequest struct {
	BlindedElements []*eccgroup.Element
}

// EvaluationResponse identify the message send from server to client
// as evaluation operation response
type EvaluationResponse struct {
	Proof             []byte
	EvaluatedElements []*eccgroup.Element
}

// FinalizeData identify the state to keep on client
type FinalizeData struct {
	EvalRequest *EvaluationRequest
	Inputs      [][]byte
	Blinds      []*eccgroup.Scalar
}
