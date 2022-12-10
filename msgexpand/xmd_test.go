// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package msgexpand

import (
	"fmt"
	"testing"

	"github.com/cymony/cryptomony/hash"
	"github.com/cymony/cryptomony/internal/test"
)

func TestXMDExpandErrors(t *testing.T) {
	testCases := []struct { //nolint:govet //just test struct
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

	allHashings := []hash.Hashing{
		hash.SHA224,
		hash.SHA256,
		hash.SHA384,
		hash.SHA512,
		hash.SHA3_224,
		hash.SHA3_256,
		hash.SHA3_384,
		hash.SHA3_512,
		hash.SHA512_224,
		hash.SHA512_256,
		hash.BLAKE2s_256,
		hash.BLAKE2b_256,
		hash.BLAKE2b_384,
		hash.BLAKE2b_512,
	}

	for _, h := range allHashings {
		for _, tstCase := range testCases {
			t.Run(fmt.Sprintf("%s_%s", h.New().String(), tstCase.name), func(t *testing.T) {
				e := NewMessageExpandXMD(h)

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
