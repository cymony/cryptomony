// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utils_test

import (
	"fmt"
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/cymony/cryptomony/internal/test"
	"github.com/cymony/cryptomony/utils"
)

func TestI2OSP(t *testing.T) {
	tests := []struct { //nolint:govet //test struct
		name    string
		x       int
		xLen    int
		want    []byte
		wantErr bool
	}{
		{
			name:    "negative int",
			x:       -1,
			xLen:    1,
			wantErr: true,
		},
		{
			name:    "integer too large #1",
			x:       math.MaxInt64,
			xLen:    1,
			wantErr: true,
		},
		{
			name: "I2OSP(0, 2)",
			x:    0,
			xLen: 2,
			want: []byte{0x00, 0x00},
		},
		{
			name: "I2OSP(1, 2)",
			x:    1,
			xLen: 2,
			want: []byte{0x00, 0x01},
		},
		{
			name: "I2OSP(255, 2)",
			x:    255,
			xLen: 2,
			want: []byte{0x00, 0xff},
		},
		{
			name: "I2OSP(256, 2)",
			x:    256,
			xLen: 2,
			want: []byte{0x01, 0x00},
		},
		{
			name: "I2OSP(65535, 2)",
			x:    65535,
			xLen: 2,
			want: []byte{0xff, 0xff},
		},
		{
			name: "I2OSP(1234, 5)",
			x:    1234,
			xLen: 5,
			want: []byte{0x00, 0x00, 0x00, 0x04, 0xd2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf, err := utils.I2osp(big.NewInt(int64(tt.x)), tt.xLen)
			if tt.wantErr {
				test.CheckIsErr(t, err, fmt.Sprintf("error should be returned when x: %d, xLen %d", tt.x, tt.xLen))
				return
			}
			if got := buf; !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				test.Report(t, got, tt.want, fmt.Sprintf("x: %d", tt.x), fmt.Sprintf("xLen: %d", tt.xLen))
			}
		})
	}
}

func TestOS2IP(t *testing.T) {
	tests := []struct { //nolint:govet //test struct
		name string
		x    []byte
		want *big.Int
	}{
		{
			name: "Expect1",
			x:    []byte{1},
			want: new(big.Int).SetInt64(1),
		},
		{
			name: "Expect65535",
			x:    []byte{255, 255},
			want: new(big.Int).SetInt64(65535),
		},
		{
			name: "Expect65536",
			x:    []byte{1, 0, 0},
			want: new(big.Int).SetInt64(65536),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := utils.Os2ip(tt.x)
			if tt.want.Int64() != int64(got) {
				test.Report(t, got, tt.want, fmt.Sprintf("x: %x", tt.x))
			}
		})
	}
}
