// Copyright (c) 2022 Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package eccgroup

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cymony/cryptomony/internal/test"
)

func TestHashToElement(t *testing.T) {
	fileNames, err := filepath.Glob("./testdata/P*.json")
	test.CheckNoErr(t, err, "filepath.Glob error")

	for _, fileName := range fileNames {
		f, err := os.Open(fileName)
		test.CheckNoErr(t, err, "os.Open err")

		dec := json.NewDecoder(f)

		var v vectorSuite
		err = dec.Decode(&v)
		test.CheckNoErr(t, err, "decode err")

		err = f.Close()
		test.CheckNoErr(t, err, "file close err")

		t.Run(v.Ciphersuite, func(t *testing.T) { testHashing(t, &v) })
	}
}

func testHashing(t *testing.T, vs *vectorSuite) {
	t.Helper()

	var G Group

	switch vs.Ciphersuite {
	case P256Sha256.String(), "P256_XMD:SHA-256_SSWU_NU_":
		G = P256Sha256
	case P384Sha384.String(), "P384_XMD:SHA-384_SSWU_NU_":
		G = P384Sha384
	case P521Sha512.String(), "P521_XMD:SHA-512_SSWU_NU_":
		G = P521Sha512
	default:
		t.Fatal("non supported suite")
	}

	hashFunc := G.HashToGroup

	if !vs.RandomOracle {
		hashFunc = G.EncodeToGroup
	}

	want := G.NewElement()

	for i, v := range vs.Vectors {
		got := hashFunc([]byte(v.Msg), []byte(vs.Dst))

		err := want.UnmarshalBinary(v.P.toBytes())
		if err != nil {
			t.Fatal(err)
		}

		if !(got.Equal(want) == 1) {
			test.Report(t, got, want, i)
		}
	}
}

type vectorSuite struct { //nolint:govet // because of it is test
	L            string `json:"L"`
	Z            string `json:"Z"`
	Ciphersuite  string `json:"ciphersuite"`
	Curve        string `json:"curve"`
	Dst          string `json:"dst"`
	Expand       string `json:"expand"`
	Hash         string `json:"hash"`
	K            string `json:"k"`
	RandomOracle bool   `json:"randomOracle"`
	Map          struct {
		Name string `json:"name"`
	} `json:"map"`
	Field struct {
		M string `json:"m"`
		P string `json:"p"`
	} `json:"field"`
	Vectors []*vector `json:"vectors"`
}

type point struct {
	X string `json:"x"`
	Y string `json:"y"`
}

func (p point) toBytes() []byte {
	x, err := hex.DecodeString(p.X[2:])
	if err != nil {
		panic(err)
	}

	y, err := hex.DecodeString(p.Y[2:])
	if err != nil {
		panic(err)
	}

	return append(append([]byte{0x04}, x...), y...)
}

type vector struct {
	P   point    `json:"P"`
	Q0  point    `json:"Q0,omitempty"`
	Q1  point    `json:"Q1,omitempty"`
	Q   point    `json:"Q,omitempty"`
	Msg string   `json:"msg"`
	U   []string `json:"u"`
}

func BenchmarkHash(b *testing.B) {
	input := []byte("This is test input")
	dst := []byte("This-Is-Long-DST")

	for _, g := range allGroups {
		name := g.String()
		b.Run(name+"/HashToGroup", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				g.HashToGroup(input, dst)
			}
		})
		b.Run(name+"/HashToScalar", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				g.HashToScalar(input, dst)
			}
		})
	}
}
