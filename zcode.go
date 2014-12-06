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
	"errors"
)

// Zcode is used to encode large arbitrary byte strings (namely the
// authenticator and checksum) in zephyr when zascii would be too
// wasteful. It is a simple escaping scheme to remove NUL bytes: 00
// is replaced with FF F0, FF is replaced with FF F1.

// ErrInvalidZcode is returned when decoding invalid zcode input.
var ErrInvalidZcode = errors.New("invalid zcode")

// DecodeZcode decodes an input byte slice as zcode.
func DecodeZcode(in []byte) ([]byte, error) {
	if len(in) == 0 {
		return nil, ErrInvalidZcode
	}
	if in[0] != 'Z' {
		return nil, ErrInvalidZcode
	}

	// Compute the length.
	l := len(in) - 1
	for _, v := range in {
		if v == '\xff' {
			l--
		}
	}

	// Decode
	out := make([]byte, l)
	j := 0
	for i := 1; i < len(in); i++ {
		if in[i] == '\x00' {
			return nil, ErrInvalidZcode
		} else if in[i] == '\xff' {
			if i+1 >= len(in) {
				return nil, ErrInvalidZcode
			}
			switch in[i+1] {
			case '\xf0':
				out[j] = '\x00'
			case '\xf1':
				out[j] = '\xff'
			default:
				return nil, ErrInvalidZcode
			}
			i++
		} else {
			out[j] = in[i]
		}
		j++
	}
	if j != l {
		panic(j)
	}
	return out, nil
}

// EncodeZcode encodes an input byte slice as zcode.
func EncodeZcode(in []byte) []byte {
	// Compute the length.
	l := len(in) + 1
	for _, v := range in {
		if v == '\xff' || v == '\x00' {
			l++
		}
	}

	// Encode
	out := make([]byte, l)
	out[0] = 'Z'
	j := 1
	for _, v := range in {
		if v == '\x00' {
			out[j] = '\xff'
			out[j+1] = '\xf0'
			j += 2
		} else if v == '\xff' {
			out[j] = '\xff'
			out[j+1] = '\xf1'
			j += 2
		} else {
			out[j] = v
			j++
		}
	}
	if j != l {
		panic(j)
	}
	return out
}
