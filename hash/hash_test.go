// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hash_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/cymony/cryptomony/hash"
	"github.com/cymony/cryptomony/internal/test"
)

type vector struct {
	in, out string
	id      hash.Hashing
}

var allVectors = []vector{
	{
		id:  hash.BLAKE2b_256,
		in:  "",
		out: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
	},
	{
		id:  hash.BLAKE2b_384,
		in:  "",
		out: "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100",
	},
	{
		id:  hash.BLAKE2b_512,
		in:  "",
		out: "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
	},
	{
		id:  hash.BLAKE2s_256,
		in:  "",
		out: "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
	},
	{
		id:  hash.SHA224,
		in:  "",
		out: "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
	},
	{
		id:  hash.SHA256,
		in:  "",
		out: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	},
	{
		id:  hash.SHA384,
		in:  "",
		out: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
	},
	{
		id:  hash.SHA3_224,
		in:  "",
		out: "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
	},
	{
		id:  hash.SHA3_256,
		in:  "",
		out: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
	},
	{
		id:  hash.SHA3_384,
		in:  "",
		out: "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
	},
	{
		id:  hash.SHA3_512,
		in:  "",
		out: "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
	},
	{
		id:  hash.SHA512,
		in:  "",
		out: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
	},
	{
		id:  hash.SHA512_224,
		in:  "",
		out: "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
	},
	{
		id:  hash.SHA512_256,
		in:  "",
		out: "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
	},
}

func TestHashing(t *testing.T) {
	for _, v := range allVectors {
		t.Run(v.id.New().String(), func(t *testing.T) {
			h := v.id.New()
			if h.BlockSize() != v.id.CryptoID().New().BlockSize() {
				test.Report(t, h.BlockSize(), v.id.CryptoID().New().BlockSize(), h.String())
			}

			if h.String() != v.id.CryptoID().String() {
				test.Report(t, h.String(), v.id.CryptoID().String(), v.id.CryptoID().String())
			}

			if h.OutputSize() != v.id.CryptoID().New().Size() {
				test.Report(t, h.OutputSize(), v.id.CryptoID().New().Size(), h.String())
			}

			err := h.MustWriteAll([]byte(v.in))
			test.CheckNoErr(t, err, "err not expected write")

			out := make([]byte, h.OutputSize())

			err = h.MustReadFull(out)
			test.CheckNoErr(t, err, "err not expected read full")

			got := hex.EncodeToString(out)

			if got != v.out {
				test.Report(t, got, v.out, h.String())
			}

			inStrings := []string{"this", "is", "multiple", "string"}
			byteDatas := make([][]byte, len(inStrings))
			for _, str := range inStrings {
				byteDatas = append(byteDatas, []byte(str))
			}

			h1 := v.id.New()
			h2 := v.id.New()

			err = h1.MustWriteAll(byteDatas...)
			test.CheckNoErr(t, err, "must write err not expected")

			for _, data := range byteDatas {
				_, err = h2.Write(data)
				test.CheckNoErr(t, err, "write err not expected")
			}

			out1 := make([]byte, h1.OutputSize())

			err = h1.MustReadFull(out1)
			test.CheckNoErr(t, err, "must read err not expected")

			out2 := h2.Sum(nil)
			test.CheckNoErr(t, err, "read err not expected")

			if !bytes.Equal(out1, out2) {
				test.Report(t, out1, out2, h1.String())
			}
		})
	}
}
