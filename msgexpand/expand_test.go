// Copyright (c) 2022 The Cymony Authors. All rights reserved.
// Use of this source code is governed by a BSD-3 Clause
// license that can be found in the LICENSE file.

package msgexpand_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cymony/cryptomony/hash"
	"github.com/cymony/cryptomony/internal/test"
	"github.com/cymony/cryptomony/msgexpand"
	"github.com/cymony/cryptomony/xof"
)

func TestVectors(t *testing.T) {
	fileNames, err := filepath.Glob("./vectors/*.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, fileName := range fileNames {
		f, err := os.Open(fileName)
		if err != nil {
			t.Fatal(err)
		}

		dec := json.NewDecoder(f)

		var v tstVectorSuite

		err = dec.Decode(&v)
		if err != nil {
			t.Fatal(err)
		}

		err = f.Close()
		test.CheckNoErr(t, err, "file close err")

		t.Run(v.Name+"/"+v.Hash, func(t *testing.T) { testExpander(t, &v) })
	}
}

func testExpander(t *testing.T, vs *tstVectorSuite) {
	t.Helper()

	var e msgexpand.MessageExpand

	switch vs.Hash {
	case "SHA256":
		e = msgexpand.NewMessageExpandXMD(hash.SHA256)
	case "SHA512":
		e = msgexpand.NewMessageExpandXMD(hash.SHA512)
	case "SHAKE128":
		e = msgexpand.NewMessageExpandXOF(xof.SHAKE128, int(vs.K))
	case "SHAKE256":
		e = msgexpand.NewMessageExpandXOF(xof.SHAKE256, int(vs.K))
	default:
		t.Skip("hash not supported: " + vs.Hash)
	}

	for _, v := range vs.Tests {
		lenBytes, err := strconv.ParseUint(v.Len, 0, 64)
		test.CheckNoErr(t, err, "strconv err")

		got, err := e.Expand([]byte(v.Msg), []byte(vs.DST), int(lenBytes))
		test.CheckNoErr(t, err, "expand err")

		want, err := hex.DecodeString(v.UniformBytes)
		test.CheckNoErr(t, err, "hex decode err")

		if !bytes.Equal(got, want) {
			test.Report(t, got, want, fmt.Sprintf("%s/%s", vs.Name, vs.Hash))
		}
	}
}

type tstVectorSuite struct { //nolint:govet //just test struct
	DST   string `json:"DST"`
	Hash  string `json:"hash"`
	Name  string `json:"name"`
	K     uint   `json:"k"`
	Tests []struct {
		DstPrime     string `json:"DST_prime"`
		Len          string `json:"len_in_bytes"`
		Msg          string `json:"msg"`
		MsgPrime     string `json:"msg_prime"`
		UniformBytes string `json:"uniform_bytes"`
	} `json:"tests"`
}
