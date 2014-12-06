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
	"testing"
)

func testZAsciiPair(t *testing.T, encodedStr, decodedStr string) {
	encoded, decoded := []byte(encodedStr), []byte(decodedStr)

	if l := DecodedZAsciiLength(len(encoded)); l != len(decoded) {
		t.Errorf("DecodedZAsciiLength(%v) = %v, want %v",
			len(encoded), l, len(decoded))
	}
	if l := EncodedZAsciiLength(len(decoded)); l != len(encoded) {
		t.Errorf("EncodedZAsciiLength(%v) = %v, want %v",
			len(decoded), l, len(encoded))
	}

	dst := make([]byte, len(decoded))
	l, err := DecodeZAsciiInto(dst, encoded)
	if err != nil {
		t.Errorf("DecodeZAsciiInto(%v) failed unexpectedly: %v",
			encodedStr, err)
	} else if l != len(decoded) {
		t.Errorf("DecodeZAsciiInto(%v) wrote %v bytes, want %v",
			encodedStr, l, len(decoded))
	} else if !bytes.Equal(dst, decoded) {
		t.Errorf("DecodeZAsciiInto(%v) = %v, want %v",
			encodedStr, dst, decoded)
	}

	if dst, err := DecodeZAscii(encoded); err != nil {
		t.Errorf("DecodeZAscii(%v) failed unexpectedly: %v",
			encodedStr, err)
	} else if !bytes.Equal(dst, decoded) {
		t.Errorf("DecodeZAscii(%v) = %v, want %v",
			encodedStr, dst, decoded)
	}

	if dst := EncodeZAscii(decoded); !bytes.Equal(dst, encoded) {
		t.Errorf("EncodeZAscii(%v) = %v, want %v",
			decoded, string(dst), encodedStr)
	}
}

func testZAscii16Pair(t *testing.T, encodedStr string, val uint16) {
	encoded := []byte(encodedStr)

	v, err := DecodeZAscii16(encoded)
	if err != nil {
		t.Errorf("DecodeZAscii16(%v) failed unexpectedly: %v",
			encodedStr, err)
	} else if v != val {
		t.Errorf("DecodeZAscii16(%v) = %v, want %v",
			encodedStr, v, val)
	}

	if dst := EncodeZAscii16(val); !bytes.Equal(dst, encoded) {
		t.Errorf("EncodeZAscii16(%v) = %v, want %v",
			val, string(dst), encodedStr)
	}
}

func testZAscii32Pair(t *testing.T, encodedStr string, val uint32) {
	encoded := []byte(encodedStr)

	v, err := DecodeZAscii32(encoded)
	if err != nil {
		t.Errorf("DecodeZAscii32(%v) failed unexpectedly: %v",
			encodedStr, err)
	} else if v != val {
		t.Errorf("DecodeZAscii32(%v) = %v, want %v",
			encodedStr, v, val)
	}

	if dst := EncodeZAscii32(val); !bytes.Equal(dst, encoded) {
		t.Errorf("EncodeZAscii32(%v) = %v, want %v",
			val, string(dst), encodedStr)
	}
}

func TestZAscii(t *testing.T) {
	testZAsciiPair(t, "", "")
	testZAsciiPair(t, "0xA5", "\xa5")
	testZAsciiPair(t, "0x0102", "\x01\x02")
	testZAsciiPair(t, "0x1A2B3C", "\x1a\x2b\x3c")
	testZAsciiPair(t, "0xDEADBEEF", "\xde\xad\xbe\xef")
	testZAsciiPair(t, "0xDEADBEEF 0xABAD1DEA",
		"\xde\xad\xbe\xef\xab\xad\x1d\xea")
	testZAsciiPair(t, "0xDEADBEEF 0xABAD1DEA 0x1234",
		"\xde\xad\xbe\xef\xab\xad\x1d\xea\x12\x34")
}

func TestZAscii16(t *testing.T) {
	testZAscii16Pair(t, "0x0001", 1)
	testZAscii16Pair(t, "0xFACE", 0xface)
}

func TestZAscii32(t *testing.T) {
	testZAscii32Pair(t, "0x00000001", 1)
	testZAscii32Pair(t, "0xDEADBEEF", 0xdeadbeef)
}

func TestZDecodeZAsciiErrors(t *testing.T) {
	bad := []string{
		"0x",
		"0102",
		"0xdeadbeef",
		"0x0102 0x0304",
		"0xGG",
		"0x123",
		"0xAABBCCDD.0x11223344",
		"0xDEADBEEF ",
		"0xDEADBEEF 0",
		"0xDEADBEEF 0x",
	}
	for _, v := range bad {
		if _, err := DecodeZAscii([]byte(v)); err == nil {
			t.Errorf("DecodeZAscii(%v) unexpectedly succeeded", v)
		}
	}
}

func TestZDecodeZAscii16Errors(t *testing.T) {
	bad := []string{
		"",
		"0x12",
		"0x12 0x34",
		"0x12345678",
		"0xface",
	}
	for _, v := range bad {
		if _, err := DecodeZAscii16([]byte(v)); err == nil {
			t.Errorf("DecodeZAscii16(%v) unexpectedly succeeded", v)
		}
	}
}

func TestZDecodeZAscii32Errors(t *testing.T) {
	bad := []string{
		"",
		"0x1234",
		"0x12 0x34 0x56 0x78",
		"0x123456",
		"0xDEADBEEF 0x00",
	}
	for _, v := range bad {
		if _, err := DecodeZAscii32([]byte(v)); err == nil {
			t.Errorf("DecodeZAscii32(%v) unexpectedly succeeded", v)
		}
	}
}
