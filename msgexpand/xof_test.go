// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package msgexpand

import (
	"fmt"
	"testing"

	"github.com/cymony/cryptomony/internal/test"
	"github.com/cymony/cryptomony/xof"
)

func TestXOFExpandErrors(t *testing.T) {
	testCases := []struct { //nolint:govet //just a test struct
		name      string
		dst       []byte
		len       int
		msg       string
		wantErr   bool
		wantedErr error
	}{
		{
			name:      "ZeroLengthDst",
			dst:       make([]byte, 0),
			len:       32,
			msg:       "test",
			wantErr:   true,
			wantedErr: ErrZeroLengthDST,
		},
		{
			name:      "LowerThanRecommendedLengthOfDst",
			dst:       []byte("lower"),
			len:       32,
			msg:       "test",
			wantErr:   true,
			wantedErr: ErrRecommendedDSTLen,
		},
		{
			name:      "BiggerThan65535LengthInBytes",
			dst:       []byte("recommendedDstLength"),
			len:       65536,
			msg:       "test",
			wantErr:   true,
			wantedErr: ErrLengthTooHigh,
		},
	}

	allXOFs := []struct {
		id xof.Extendable
		k  int
	}{
		{
			id: xof.SHAKE128,
			k:  128,
		},
		{
			id: xof.SHAKE256,
			k:  256,
		},
		{
			id: xof.BLAKE2XB,
			k:  128,
		},
		{
			id: xof.BLAKE2XS,
			k:  128,
		},
	}

	for _, xo := range allXOFs {
		for _, tstCase := range testCases {
			t.Run(fmt.Sprintf("%s_%s", xo.id.New().String(), tstCase.name), func(t *testing.T) {
				e := NewMessageExpandXOF(xo.id, xo.k)
				_, err := e.Expand([]byte(tstCase.msg), tstCase.dst, tstCase.len)
				if tstCase.wantErr && err == nil {
					test.Report(t, err, tstCase.wantedErr, string(tstCase.dst), tstCase.len, tstCase.msg)
				}
				if !tstCase.wantErr && err != nil {
					test.Report(t, err, nil, string(tstCase.dst), tstCase.len, tstCase.msg)
				}
			})
		}
	}
}
