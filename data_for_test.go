// Copyright 2014 The zephyr-go authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package zephyr

import (
	"bytes"
	"encoding/base64"
	"net"
	"strings"

	"github.com/zephyr-im/krb5-go"
)

func stringsToByteSlices(ss []string) [][]byte {
	bs := make([][]byte, len(ss))
	for i := range ss {
		bs[i] = []byte(ss[i])
	}
	return bs
}

// Authenticated packets taken from a libzephyr session. (Session was
// since canceled and the ticket associate with the key has expired.)

func sampleKeyBlock() *krb5.KeyBlock {
	data, err := base64.StdEncoding.DecodeString(
		"2PgONWKpPuAyFwRRIe1Ex5bR4kLNkI9beX4NGl7mkIA=")
	if err != nil {
		panic(err)
	}
	return &krb5.KeyBlock{krb5.ENCTYPE_AES256_CTS_HMAC_SHA1_96, data}
}

func stringToUID(s string) UID {
	var uid UID
	if len(s) != 12 {
		panic(s)
	}
	copy(uid[:], []byte(s))
	return uid
}

func sampleChecksum() []byte {
	return []byte("\x39\x04\x48\x83\x3f\xa5\x59\xf2\x0f\x39\x88\x00")
}

func sampleChecksumZcode() []byte {
	return []byte("Z\x39\x04\x48\x83\x3f\xa5\x59\xf2\x0f\x39\x88\xff\xf0")
}

func samplePacket() []byte {
	return []byte("ZEPH0.2\x00" +
		"0x00000013\x00" +
		"0x00000002\x00" +
		"0x1265189F 0x532DE3FC 0x0003AC0E\x00" +
		"0xC0CA\x00" +
		"0x00000001\x00" +
		"0x00000000\x00" +
		"\x00" +
		"davidben-test-class\x00" +
		"test\x00" +
		"\x00" +
		"davidben@ATHENA.MIT.EDU\x00" +
		"\x00" +
		"http://zephyr.1ts.org/wiki/df\x00" +
		string(sampleChecksumZcode()) + "\x00" +
		"0/23\x00" +
		"0x1265189F 0x532DE3FC 0x0003AC0E\x00" +
		"Z\x12\x65\x18\x9f\x00" +
		"0x6A00\x00" +
		"David Benjamin\x00" +
		"Message\n")

}

func sampleFailPacket() []byte {
	return makeTestPacket(14,
		"Z\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c")
}

func sampleMalformedChecksumPacket() []byte {
	return makeTestPacket(14, "invalid checksum")
}

func sampleMalformedPortPacket() []byte {
	return makeTestPacket(4, "invalid port")
}

func sampleRawNotice() *RawNotice {
	return &RawNotice{
		stringsToByteSlices([]string{
			"ZEPH0.2",
			"0x00000013",
			"0x00000002",
			"0x1265189F 0x532DE3FC 0x0003AC0E",
			"0xC0CA",
			"0x00000001",
			"0x00000000",
			"",
			"davidben-test-class",
			"test",
			"",
			"davidben@ATHENA.MIT.EDU",
			"",
			"http://zephyr.1ts.org/wiki/df",
			string(sampleChecksumZcode()),
			"0/23",
			"0x1265189F 0x532DE3FC 0x0003AC0E",
			"Z\x12\x65\x18\x9f",
			"0x6A00",
		}),
		[]byte("David Benjamin\x00Message\n")}

}

func sampleNotice() *Notice {
	uid := stringToUID("\x12\x65\x18\x9F\x53\x2D\xE3\xFC\x00\x03\xAC\x0E")
	return &Notice{
		Header: Header{
			Kind:          ACKED,
			UID:           uid,
			Port:          49354,
			Class:         "davidben-test-class",
			Instance:      "test",
			OpCode:        "",
			Sender:        "davidben@ATHENA.MIT.EDU",
			Recipient:     "",
			DefaultFormat: "http://zephyr.1ts.org/wiki/df",
			SenderAddress: net.ParseIP("18.101.24.159").To4(),
			Charset:       CharsetUTF8,
			OtherFields:   [][]byte{},
		},
		Multipart: "0/23",
		MultiUID:  uid,
		RawBody:   []byte("David Benjamin\x00Message\n")}
}

func sampleNoticeWithUID(uid UID) *Notice {
	notice := sampleNotice()
	notice.UID = uid
	return notice
}

func sampleMessage(uid UID, rawBody []byte) *Message {
	return &Message{
		sampleNoticeWithUID(uid).Header,
		strings.Split(string(rawBody), "\x00")}
}

func makeTestPacket(index int, replace string) []byte {
	raw := sampleRawNotice()
	fields := make([][]byte, len(raw.HeaderFields)+1)
	copy(fields, raw.HeaderFields)
	fields[len(fields)-1] = raw.Body
	fields[index] = []byte(replace)
	return bytes.Join(fields, []byte{0})
}
