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
	hashIn, out                        string
	in, extractOut, expandOut, hmacOut string
	id                                 hash.Hashing
}

var hashVectors = []vector{
	{
		id:         hash.BLAKE2b_256,
		hashIn:     "",
		out:        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
		in:         "secret",
		extractOut: "1b599e7db43659c4d10652971d4cb0dd5562e8ed41163f557ad539b7a8ae10de",
		expandOut:  "04e573d2f76ca69c6d803585b58d79f666e5057814307edd7d9a08f18af3bbea",
		hmacOut:    "a5da17d466c8f35522d9d2e5a43bdd43c386c31c1dc8b54dc2f6ffd72870ad34",
	},
	{
		id:         hash.BLAKE2b_384,
		hashIn:     "",
		out:        "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100",
		in:         "secure",
		extractOut: "52c1f5ded1f4bd63015e7608c21b4d34b479301d6b040d5bf9399c759c58903341544e7ca3d4a7d8f4aaea8dc7927c16",
		expandOut:  "bc1437d6744e8664d74b8c9a85d1cbd5834b9e477ad2479711c79906a2f39461f2bf20953e575fbcf241338724cbdfe0",
		hmacOut:    "3356cde87b7a68947caa0592332f96ff2580bee3b3e52f0a898cde59543eaa9e452e7b3a5b4e43384199a962bac9b604",
	},
	{
		id:         hash.BLAKE2b_512,
		hashIn:     "",
		out:        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
		in:         "ss",
		extractOut: "73ddd9188b500a721b8411ffb5992d554b04e79eeb6714628e038b9fad333b7c0da15ac8b058c8dad5f5dcd6c0868c70705df0a22cdecde0fcd39cf7bea5cff7",
		expandOut:  "a2f2a2052f8b4b4261ab94f1affc843cb6317310a9e8611f7707c68d14f7869c6c1f490bf43b9891527a1a9ee67a181fd801f9d5d0cd5c0f9cead7b5bc6a309c",
		hmacOut:    "0d9f4328b1eb897c7e14b5e059aa2b7bbebfdf2d03707ea02404c4558d327908aa070e972ca9d9e4bc5733f4a4e0a72e5d9601debbb2b418c41b35f0b8445ad1",
	},
	{
		id:         hash.BLAKE2s_256,
		hashIn:     "",
		out:        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
		in:         "aa",
		extractOut: "6c193101fa593b41a57d21421c36cb7779d354c4597730f8994155e189be6ee6",
		expandOut:  "90a022153eddfeb2d6cee2781795b021953a72bbec83242d1c0cae66c3937b8e",
		hmacOut:    "8f818f9e6a6a93ce2c80b9ed2d1a21f74c668adb068214d213fe2980c8500be0",
	},
	{
		id:         hash.SHA224,
		hashIn:     "",
		out:        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
		in:         "bb",
		extractOut: "330ecc40658b35d90d6481d5603ef8745b684d013603d44565a77c34",
		expandOut:  "734a724d0b92535b721651a4ba08a6c96f19c3e08ec92752c67c65af",
		hmacOut:    "4cc2bad9f029dafeeefb6e20e8d023ff8b961e283f505bbc3081696a",
	},
	{
		id:         hash.SHA256,
		hashIn:     "",
		out:        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		in:         "adadadad",
		extractOut: "5d68f7e5f1d97aceed628c176d40fe37441a39bf5f6ded9e80308ecb86b0baa4",
		expandOut:  "e6d188875fb3b34092fbbe1c13f1581d5c2dd369cb7b3ef3eb276a380fcd0f7b",
		hmacOut:    "3831f307e99af4456168747f5d35f58ec4c5b0b611814c5e7d955b638b637a40",
	},
	{
		id:         hash.SHA384,
		hashIn:     "",
		out:        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		in:         "asasasasa",
		extractOut: "67b9df66ec532f16d3100b5db6b3873a194ccd43cd6792324612d8adaacdd2d8b507577ad052bcff3ebbd793ce40d239",
		expandOut:  "3692431922d9512808168e87ee3310d53458283af4302eec03653327e222e8daad16b7176c43d7bc3a5862c24ad5be55",
		hmacOut:    "653f9456739384b2cb5fa4bc6b294b591f6edae94611278969f11c7962711b31720cde5b8d4e3995d91e63dff53f15c3",
	},
	{
		id:         hash.SHA3_224,
		hashIn:     "",
		out:        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
		in:         "weqweqwe",
		extractOut: "0b24a865679748a9f8b948cdd7972f7d4bf7e276d98d84506f7361f2",
		expandOut:  "19bca55548e22c0a1375894c2d7810af2351b279a3288bbbb076e9ce",
		hmacOut:    "6f49980f407cefac94f4c37992b161cc6e4bb5f04b3a75dfa6d9c2a5",
	},
	{
		id:         hash.SHA3_256,
		hashIn:     "",
		out:        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		in:         "secsec",
		extractOut: "eba65549d3dcd552db8f7b358a8dd88814dd4c959de197ee48a1b71bf6c05b99",
		expandOut:  "5ba3bb512c40adf50399bb82965b485e13fdc6b9877c54fb669ec39b36d36440",
		hmacOut:    "90d3e8c4c70cb9b139b7c3a4ee2a8ab5908eb9d39576fcb3ec86c3ceb870f020",
	},
	{
		id:         hash.SHA3_384,
		hashIn:     "",
		out:        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
		in:         "olololololo",
		extractOut: "b6813578703beeb36c2037b136e0471da98483f3eb521196be39ac0dfa3f8f103ef0be5a9d745fa64956263e4eded995",
		expandOut:  "0934c7bae93bc3309647e45d7a00b2bc77b6698814ab35185602abeb51592ec110eb0d1bd54808d97fb28540e5817ff6",
		hmacOut:    "275ef138231f6259865423433899faf6c32f8ab603d00684062d8eb4c68f29bfab983a4d1d1e086c081925890099eab0",
	},
	{
		id:         hash.SHA3_512,
		hashIn:     "",
		out:        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
		in:         "adadadadad",
		extractOut: "72de1d3bd1bc8a0058947a1d34a1a4daa4058159429375dcabb6cdb7d6d69fea5ab7089fe6be4f7d75bec3c6f64acd760d9f3eb808973002a54b028b1ad2dc3f",
		expandOut:  "5597e66cf909f1a4d2a2dbfea50e0384aaf2b755aed4a69c7b9dd2d90d36199eb7c4d9e3f20fd7bd0e02067f9f5d1acf75f7451db92e16a96ec3b878f97dc3cf",
		hmacOut:    "b7c8a9620c3ab8c2ac24328ebac689a103555866e1633fbbf62f636ce1503e46daa8d7d673ecf134c093160e383230190654da545628a655d06772f9e786a5f6",
	},
	{
		id:         hash.SHA512,
		hashIn:     "",
		out:        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		in:         "secrettt",
		extractOut: "231240613c5a32a0ec806f22fe7b45edf1868e58394eea944e6fc6c4764823a2608b3a7d78460237ce7761cc4b5c8b449d8d78a04441fdee3a5c69716926d4d7",
		expandOut:  "e9f4c08fef06a37dce03fda71b4b2b161865f4a0ad9c0074f986a5b0002ffe4cc2c3fba68f8935eb800bd6a7e5b885fef4d91b968eba8538c7d878cdc917e9f5",
		hmacOut:    "640e24c0600d977d8d64aeb654aa11569c55b4e0c210d58203eaf5d15828cf7b78d33a3a8f950a439aa3b7f2074a8ce7f8629064ca6d11ac68f241addd6736c5",
	},
	{
		id:         hash.SHA512_224,
		hashIn:     "",
		out:        "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
		in:         "secure",
		extractOut: "d56bd815527208d5bc9e73142235c63e9656f7fc91418309e043921e",
		expandOut:  "43776c51c46cafe92f8dbe8a48a8c5b1b03081a55fa9088fb8c7d9f8",
		hmacOut:    "ca683430be15889419dffe78898e4541039cc6b5f87cccd58075b747",
	},
	{
		id:         hash.SHA512_256,
		hashIn:     "",
		out:        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
		in:         "secsecret",
		extractOut: "b824f79e6d13dac558cd9506a52443e5415a080805ac825fdf2229f216d14f02",
		expandOut:  "605e02647166abb90d1184939b45126554136df8e81778766a3b4f21b292b675",
		hmacOut:    "3dae4d61efaecb6ca784a101d0b9a9c1fc786a554b1eb564661c6c985097bdca",
	},
}

func TestHashing(t *testing.T) {
	for _, v := range hashVectors {
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

			err := h.MustWriteAll([]byte(v.hashIn))
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

func TestExtract(t *testing.T) {
	for _, v := range hashVectors {
		t.Run(v.id.New().String(), func(t *testing.T) {
			h := v.id.New()
			got := h.HKDFExtract([]byte(v.in), nil)

			want, err := hex.DecodeString(v.extractOut)
			test.CheckNoErr(t, err, "hex decode err")
			if !bytes.Equal(got, want) {
				test.Report(t, got, want, "bytes not equal")
			}
		})
	}
}

func TestExpand(t *testing.T) {
	for _, v := range hashVectors {
		t.Run(v.id.New().String(), func(t *testing.T) {
			h := v.id.New()

			got := h.HKDFExpand([]byte(v.in), nil, 0)

			want, err := hex.DecodeString(v.expandOut)
			test.CheckNoErr(t, err, "hex decode err")
			if !bytes.Equal(got, want) {
				test.Report(t, got, want, "bytes not equal")
			}
		})
	}
}

func TestHmac(t *testing.T) {
	for _, v := range hashVectors {
		t.Run(v.id.New().String(), func(t *testing.T) {
			h := v.id.New()
			got, err := h.Hmac([]byte("message"), []byte(v.in))
			test.CheckNoErr(t, err, "hmac err")

			want, err := hex.DecodeString(v.hmacOut)
			test.CheckNoErr(t, err, "hex decode err")
			if !bytes.Equal(got, want) {
				test.Report(t, got, want, "bytes not equal")
			}
		})
	}
}
