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

func testZcodePair(t *testing.T, encodedStr, decodedStr string) {
	encoded, decoded := []byte(encodedStr), []byte(decodedStr)

	if ret := EncodeZcode(decoded); !bytes.Equal(ret, encoded) {
		t.Errorf("EncodeZcode(%v) = %v, want %v",
			decoded, ret, encoded)
	}

	ret, err := DecodeZcode(encoded)
	if err != nil {
		t.Errorf("DecodeZcode(%v) failed unexpectedly: %v",
			encoded, err)
	} else if !bytes.Equal(ret, decoded) {
		t.Errorf("DecodeZcode(%v) = %v, want %v",
			encoded, ret, decoded)
	}
}

func TestZcode(t *testing.T) {
	testZcodePair(t, "Z", "")
	testZcodePair(t, "Zabcdef", "abcdef")
	testZcodePair(t, "Z\xff\xf0", "\x00")
	testZcodePair(t, "Z\xff\xf1", "\xff")
	testZcodePair(t, "Z\xff\xf1abc\xff\xf0def", "\xffabc\x00def")
}

func TestDecodeZcodeErrors(t *testing.T) {
	bad := []string{
		"",
		"abc",
		"zabc",
		"Zab\x00cd",
		"Z\xff",
		"Z\xff\x80",
		"Z\xff\xf2",
	}
	for _, v := range bad {
		if _, err := DecodeZcode([]byte(v)); err == nil {
			t.Errorf("DecodeZcode(%v) unexpectedly succeeded", v)
		}
	}

}
