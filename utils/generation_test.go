// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package utils_test

import (
	"testing"

	"github.com/cymony/cryptomony/internal/test"
	"github.com/cymony/cryptomony/utils"
)

func TestRandomBytes(t *testing.T) {
	tests := []struct {
		name     string
		lenBytes int
		wantLen  int
	}{
		{
			name:     "64 bytes",
			lenBytes: 64,
			wantLen:  64,
		},
		{
			name:     "32 bytes",
			lenBytes: 32,
			wantLen:  32,
		},
		{
			name:     "24 bytes",
			lenBytes: 24,
			wantLen:  24,
		},
		{
			name:     "8 bytes",
			lenBytes: 8,
			wantLen:  8,
		},
	}

	testTimes := 1 << 7
	for i := 0; i < testTimes; i++ {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := test.CheckPanic(func() {
					gotBytes := utils.RandomBytes(tt.lenBytes)
					if len(gotBytes) != tt.wantLen {
						test.Report(t, len(gotBytes), tt.wantLen, tt.lenBytes)
					}
				})
				test.CheckIsErr(t, err, "panic occurred")
			})
		}
	}
}
