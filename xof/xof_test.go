// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package xof_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/cymony/cryptomony/internal/test"
	"github.com/cymony/cryptomony/xof"
)

type vector struct {
	in, out string
	outLen  int
	id      xof.Extendable
}

var allVectors = []vector{
	{
		id:     xof.SHAKE128,
		in:     "",
		out:    "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
		outLen: 32,
	},
	{
		id:     xof.SHAKE256,
		in:     "",
		out:    "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
		outLen: 64,
	},
	{
		id:     xof.SHAKE128,
		in:     "The quick brown fox jumps over the lazy dog",
		out:    "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e",
		outLen: 32,
	},
	{
		id:     xof.SHAKE128,
		in:     "The quick brown fox jumps over the lazy dof",
		out:    "853f4538be0db9621a6cea659a06c1107b1f83f02b13d18297bd39d7411cf10c",
		outLen: 32,
	},
	{
		id:     xof.BLAKE2XB,
		in:     "The quick brown fox jumps over the lazy dog",
		out:    "364e84ca4c103df292306c93ebba6f6633d5e9cc8a95e040498e9a012d5ca534",
		outLen: 32,
	},
	{
		id:     xof.BLAKE2XS,
		in:     "The quick brown fox jumps over the lazy dog",
		out:    "0650cde4df888a06eada0f0fecb3c17594304b4a03fdd678182f27db1238b174",
		outLen: 32,
	},
}

func TestXof(t *testing.T) {
	for i, v := range allVectors {
		x := v.id.New()
		_, err := x.Write([]byte(v.in))
		test.CheckNoErr(t, err, "write error not expected")

		got := make([]byte, v.outLen)
		want, err := hex.DecodeString(v.out)
		test.CheckNoErr(t, err, "decode string err")

		for _, x := range []io.Reader{x, x.Clone()} {
			n, err := x.Read(got)
			test.CheckNoErr(t, err, "read error not expected")

			if n != v.outLen || !bytes.Equal(got, want) {
				test.Report(t, got, want, i, v.id)
			}
		}
	}

	err := test.CheckPanic(func() {
		var nonID xof.Extendable
		nonID.New()
	})
	test.CheckNoErr(t, err, "panic expected")

	if err != nil {
		t.Errorf("expected that error not returned but got err: %v", err)
	}
}

func TestMustReadAndWrite(t *testing.T) {
	testDatas := struct {
		inStrings []string
		xofs      []struct {
			id     xof.Extendable
			outLen int
		}
	}{
		inStrings: []string{"this", "is", "multiple", "string"},
		xofs: []struct {
			id     xof.Extendable
			outLen int
		}{
			{
				id:     xof.SHAKE128,
				outLen: 32,
			},
			{
				id:     xof.SHAKE256,
				outLen: 64,
			},
			{
				id:     xof.BLAKE2XB,
				outLen: 32,
			},
			{
				id:     xof.BLAKE2XS,
				outLen: 32,
			},
		},
	}

	byteDatas := make([][]byte, len(testDatas.inStrings))
	for _, str := range testDatas.inStrings {
		byteDatas = append(byteDatas, []byte(str))
	}

	for _, x := range testDatas.xofs {
		t.Run(x.id.New().String(), func(t *testing.T) {
			h1 := x.id.New()
			h2 := x.id.New()

			err := h1.MustWriteAll(byteDatas...)
			test.CheckNoErr(t, err, "must write err not expected")

			for _, data := range byteDatas {
				_, err = h2.Write(data)
				test.CheckNoErr(t, err, "write err not expected")
			}

			out1 := make([]byte, x.outLen)
			out2 := make([]byte, x.outLen)

			err = h1.MustReadFull(out1)
			test.CheckNoErr(t, err, "must read err not expected")

			_, err = h2.Read(out2)
			test.CheckNoErr(t, err, "read err not expected")

			if !bytes.Equal(out1, out2) {
				test.Report(t, "not equal", "equal", out1, out2)
			}
		})
	}
}
