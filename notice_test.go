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
	"net"
	"reflect"
	"testing"
	"time"
)

func expectHeadersEqual(t *testing.T, a *Header, b *Header) {
	if a.Kind != b.Kind {
		t.Errorf("Kind = %v; want %v", a.Kind, b.Kind)
	}
	if !a.UID.Equal(b.UID) {
		t.Errorf("UID = %v; want %v", a.UID, b.UID)
	}
	if a.Port != b.Port {
		t.Errorf("Port = %v; want %v", a.Port, b.Port)
	}
	if a.Class != b.Class {
		t.Errorf("Class = %v; want %v", a.Class, b.Class)
	}
	if a.Instance != b.Instance {
		t.Errorf("Instance = %v; want %v", a.Instance, b.Instance)
	}
	if a.OpCode != b.OpCode {
		t.Errorf("OpCode = %v; want %v", a.OpCode, b.OpCode)
	}
	if a.Sender != b.Sender {
		t.Errorf("Sender = %v; want %v", a.Sender, b.Sender)
	}
	if a.Recipient != b.Recipient {
		t.Errorf("Recipient = %v; want %v", a.Recipient, b.Recipient)
	}
	if a.DefaultFormat != b.DefaultFormat {
		t.Errorf("DefaultFormat = %v; want %v", a.DefaultFormat, b.DefaultFormat)
	}
	if !a.SenderAddress.Equal(b.SenderAddress) {
		t.Errorf("SenderAddress = %v; want %v", a.SenderAddress, b.SenderAddress)
	}
	if a.Charset != b.Charset {
		t.Errorf("Charset = %v; want %v", a.Charset, b.Charset)
	}
	if !reflect.DeepEqual(a.OtherFields, b.OtherFields) {
		t.Errorf("OtherFields = %v; want %v", a.OtherFields, b.OtherFields)
	}
}

func expectNoticesEqual(t *testing.T, a *Notice, b *Notice) {
	expectHeadersEqual(t, &a.Header, &b.Header)
	if a.Multipart != b.Multipart {
		t.Errorf("Multipart = %v; want %v", a.Multipart, b.Multipart)
	}
	if !a.MultiUID.Equal(b.MultiUID) {
		t.Errorf("MultiUID = %v; want %v", a.MultiUID, b.MultiUID)
	}
	if !bytes.Equal(a.RawBody, b.RawBody) {
		t.Errorf("RawBody = %q; want %q", a.RawBody, b.RawBody)
	}
}

func TestDecodeUID(t *testing.T) {
	field := "0x1209400D 0x532A6AC4 0x0005385B"
	uid := stringToUID("\x12\x09\x40\x0D\x53\x2A\x6A\xC4\x00\x05\x38\x5B")
	if out, err := decodeUID([]byte(field)); err != nil {
		t.Errorf("decodeUID(%q) failed: %v", field, err)
	} else if string(out[:]) != string(uid[:]) {
		t.Errorf("decodeUID(%q) = %v; want %v", field, &uid, out)
	}

	if _, err := decodeUID([]byte("0x1209400D")); err != ErrBadField {
		t.Errorf("decodeUID(%q) gave bad error: %v", "0x1209400D", err)
	}

	if _, err := decodeUID([]byte("?" + field[1:])); err == nil {
		t.Errorf("decodeUID(%q) unexpected succeeded", "bogus")
	}
}

func TestUID(t *testing.T) {
	uid := stringToUID("\x12\x09\x40\x0D\x53\x2A\x6A\xC4\x00\x05\x38\x5B")

	if ip := uid.IP(); !ip.Equal(net.ParseIP("18.9.64.13")) {
		t.Errorf("uid.IP() = %v; want 18.9.64.13", ip)
	}

	expectedTime := time.Unix(0x532A6AC4, 0x0005385B*1000)
	if time := uid.Time(); !time.Equal(expectedTime) {
		t.Errorf("uid.Time() = %v; want %v", time, expectedTime)
	}

	if uid2 := MakeUID(uid.IP(), uid.Time()); uid2 != uid {
		t.Errorf("MakeUID() = %v; want %v", uid2, uid)
	}
}

func TestDecodeNotice(t *testing.T) {
	// Test that the raw notice decodes as expected.
	raw := sampleRawNotice()
	expected := sampleNotice()
	if notice, err := DecodeRawNotice(raw); err != nil {
		t.Errorf("DecodeRawNotice(%v) failed: %v", raw, err)
	} else {
		expectNoticesEqual(t, notice, expected)
	}

	// Value in sender address takes precedence over UID value.
	raw.HeaderFields[17] = []byte("Z\x08\x08\x08\x08")
	expected.SenderAddress = net.ParseIP("8.8.8.8").To4()
	if notice, err := DecodeRawNotice(raw); err != nil {
		t.Errorf("DecodeRawNotice(%v) failed: %v", raw, err)
	} else {
		expectNoticesEqual(t, notice, expected)
	}

	raw = sampleRawNotice()
	expected = sampleNotice()

	// No charset.
	raw.HeaderFields = raw.HeaderFields[0:18]
	expected.Charset = CharsetUnknown
	if notice, err := DecodeRawNotice(raw); err != nil {
		t.Errorf("DecodeRawNotice(%v) failed: %v", raw, err)
	} else {
		expectNoticesEqual(t, notice, expected)
	}

	// No sender address specified. Still get an IP address from the UID.
	raw.HeaderFields = raw.HeaderFields[0:17]
	if notice, err := DecodeRawNotice(raw); err != nil {
		t.Errorf("DecodeRawNotice(%v) failed: %v", raw, err)
	} else {
		expectNoticesEqual(t, notice, expected)
	}

	// No multiuid.
	raw.HeaderFields = raw.HeaderFields[0:16]
	expected.MultiUID = expected.UID
	expected.Multipart = ""
	if notice, err := DecodeRawNotice(raw); err != nil {
		t.Errorf("DecodeRawNotice(%v) failed: %v", raw, err)
	} else {
		expectNoticesEqual(t, notice, expected)
	}

	// No multipart.
	raw.HeaderFields = raw.HeaderFields[0:15]
	if notice, err := DecodeRawNotice(raw); err != nil {
		t.Errorf("DecodeRawNotice(%v) failed: %v", raw, err)
	} else {
		expectNoticesEqual(t, notice, expected)
	}

	// Extra fields.
	raw = sampleRawNotice()
	expected = sampleNotice()
	raw.HeaderFields = append(raw.HeaderFields, []byte("extra"))
	expected.OtherFields = [][]byte{[]byte("extra")}
	if notice, err := DecodeRawNotice(raw); err != nil {
		t.Errorf("DecodeRawNotice(%v) failed: %v", raw, err)
	} else {
		expectNoticesEqual(t, notice, expected)
	}

	// Test some bad packets.
	indices := []int{2, 3, 4, 16, 17, 18}
	for _, idx := range indices {
		raw := sampleRawNotice()
		raw.HeaderFields[idx] = []byte("bogus")
		if _, err := DecodeRawNotice(raw); err == nil {
			t.Errorf("Bad header %d unexpectedly succeeded", idx)
		}
	}

	// IP parses but has a bad length.
	raw = sampleRawNotice()
	raw.HeaderFields[17] = []byte("Zabc")
	if _, err := DecodeRawNotice(raw); err == nil {
		t.Errorf("Short IP unexpectedly succeeded")
	}
}

func zeroByteSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func TestDecodeNoticeAliasing(t *testing.T) {
	// Test that DecodeRawNotice's result doesn't alias the input.
	raw := sampleRawNotice()
	expected := sampleNotice()
	notice, err := DecodeRawNotice(raw)
	if err != nil {
		t.Errorf("DecodeRawNotice(%v) failed: %v", raw, err)
	} else {
		expectNoticesEqual(t, notice, expected)
	}

	for _, h := range raw.HeaderFields {
		zeroByteSlice(h)
	}
	zeroByteSlice(raw.Body)

	expectNoticesEqual(t, notice, expected)
}

func TestEncRawNoticeUnauth(t *testing.T) {
	raw := sampleRawNotice()
	// AuthNo = 0
	raw.HeaderFields[5] = []byte("0x00000000")
	// No authenticator.
	raw.HeaderFields[6] = []byte("0x00000000")
	raw.HeaderFields[7] = []byte("")
	// No checksum.
	raw.HeaderFields[14] = []byte("")

	if enc := sampleNotice().EncodeRawNoticeUnauth(); !reflect.DeepEqual(enc, raw) {
		t.Errorf("EncodeRawNoticeUnauth()\n = %v\nwant %v", enc, raw)
	}
}
