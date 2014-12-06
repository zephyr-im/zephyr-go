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
	"encoding/binary"
	"errors"
)

// The zephyrascii implementation is going to intentionally be
// stricter than libzephyr's for now. Byte sequences MUST be bracketed
// at every word and MUST be uppercase.

const upperHexTable = "0123456789ABCDEF"

// The encoded length of a zephyrascii word.
const zephyrasciiWordLength = 2 + 2*4

// DecodedZAsciiLength returns the decoded length of a zephyrascii
// input of length n.
func DecodedZAsciiLength(n int) int {
	if n == 0 {
		return 0
	}
	result := 4 * (n / (zephyrasciiWordLength + 1))
	result += ((n % (zephyrasciiWordLength + 1)) - 2) / 2
	return result
}

func decodeUpperHexChar(c byte) (byte, error) {
	if '0' <= c && c <= '9' {
		return c - '0', nil
	} else if 'A' <= c && c <= 'F' {
		return c - 'A' + 10, nil
	} else {
		return 0, errors.New("bad hex character")
	}
}

func decodeUpperHex(dst, src []byte) (int, error) {
	if len(src)%2 != 0 {
		return 0, errors.New("bad hex length")
	}
	for i := 0; i < len(src)/2; i++ {
		hi, err := decodeUpperHexChar(src[2*i])
		if err != nil {
			return 0, err
		}
		lo, err := decodeUpperHexChar(src[2*i+1])
		if err != nil {
			return 0, err
		}
		dst[i] = (hi<<4 | lo)
	}
	return len(src) / 2, nil
}

// DecodeZAsciiInto decodes zephyrascii from src and writes the output
// into dst. It returns the number of bytes written.
func DecodeZAsciiInto(dst, src []byte) (int, error) {
	if len(src) == 0 {
		return 0, nil
	}

	// Check the lengths ahead of time.
	lastLen := len(src) % (zephyrasciiWordLength + 1)
	if lastLen < 2+2 || lastLen%2 != 0 {
		return 0, errors.New("bad zephyrascii field length")
	}

	j := 0
	for i := 0; i < len(src); i += zephyrasciiWordLength + 1 {
		if i > 0 && src[i-1] != ' ' {
			return 0, errors.New("expected ' '")
		}
		if src[i] != '0' || src[i+1] != 'x' {
			return 0, errors.New("expected '0x'")
		}
		limit := i + zephyrasciiWordLength
		if limit > len(src) {
			limit = len(src)
		}
		decoded, err := decodeUpperHex(dst[j:], src[i+2:limit])
		if err != nil {
			return 0, err
		}
		j += decoded
	}
	return j, nil
}

// DecodeZAscii decodes zephyrascii and returns the decoded result as
// a byte slice.
func DecodeZAscii(src []byte) ([]byte, error) {
	dst := make([]byte, DecodedZAsciiLength(len(src)))
	if l, err := DecodeZAsciiInto(dst, src); err != nil {
		return nil, err
	} else if l != len(dst) {
		panic(l)
	}
	return dst, nil
}

// DecodeZAscii16 decodes the zephyrascii encoding of a 16-bit integer
// and returns the result as a uint16.
func DecodeZAscii16(src []byte) (uint16, error) {
	if len(src) != 2+2*2 {
		return 0, errors.New("bad length for uint16 zephyrascii")
	}
	dst, err := DecodeZAscii(src)
	if err != nil {
		return 0, err
	}
	if len(dst) != 2 {
		panic(dst)
	}
	return binary.BigEndian.Uint16(dst), nil
}

// DecodeZAscii32 decodes the zephyrascii encoding of a 32-bit integer
// and returns the result as a uint32.
func DecodeZAscii32(src []byte) (uint32, error) {
	if len(src) != 2+2*4 {
		return 0, errors.New("bad length for uint32 zephyrascii")
	}
	dst, err := DecodeZAscii(src)
	if err != nil {
		return 0, err
	}
	if len(dst) != 4 {
		panic(dst)
	}
	return binary.BigEndian.Uint32(dst), nil
}

// EncodedZAsciiLength returns the length of the zephyrascii encoding
// of a byte slice of length n.
func EncodedZAsciiLength(n int) int {
	if n == 0 {
		return 0
	}
	fullWords := (n / 4) * (zephyrasciiWordLength + 1)
	rest := n % 4
	if rest == 0 {
		// Remove trailing space.
		return fullWords - 1
	}
	// Account for 0x and remainder.
	return fullWords + 2 + rest*2
}

// EncodeZAscii encodes a byte slice as zephyrascii.
func EncodeZAscii(src []byte) []byte {
	dst := make([]byte, EncodedZAsciiLength(len(src)))
	j := 0
	for i, v := range src {
		if i%4 == 0 {
			if i > 0 {
				dst[j] = ' '
				j++
			}
			dst[j] = '0'
			dst[j+1] = 'x'
			j += 2
		}
		dst[j] = upperHexTable[v>>4]
		dst[j+1] = upperHexTable[v&0xf]
		j += 2
	}
	return dst
}

// EncodeZAscii16 encodes a 16-bit integer as zephyrascii.
func EncodeZAscii16(val uint16) []byte {
	src := make([]byte, 2)
	binary.BigEndian.PutUint16(src, val)
	return EncodeZAscii(src)
}

// EncodeZAscii32 encodes a 32-bit integer as zephyrascii.
func EncodeZAscii32(val uint32) []byte {
	src := make([]byte, 4)
	binary.BigEndian.PutUint32(src, val)
	return EncodeZAscii(src)
}
