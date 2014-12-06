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
	"fmt"
	"strconv"
	"strings"
)

// MaxMessageBodyLength is the maximum length of a reassembled message
// body.
const MaxMessageBodyLength = 400000

// ErrBodyTooLong is returned if the reassembled body is too long.
var ErrBodyTooLong = errors.New("reassembled body too long")

// ErrBodyLengthMismatch is returned if a notice's body length field
// is incompatible the reassembler being used.
var ErrBodyLengthMismatch = errors.New("reassembled body length mismatch")

// ErrBodyFragmentOutOfBounds is returned if a notice's body is out of
// bounds of the reassembled message body.
var ErrBodyFragmentOutOfBounds = errors.New("message fragment out of bounds")

// ParseMultipart parses the multipart field of a notice. It returns
// the part and partof parts of the field. On parse error, it returns
// 0 and the length of the body.
func ParseMultipart(n *Notice) (int, int) {
	ss := strings.Split(n.Multipart, "/")
	if len(ss) != 2 {
		return 0, len(n.RawBody)
	}
	part, err := strconv.ParseInt(ss[0], 10, 0)
	if err != nil || part < 0 {
		return 0, len(n.RawBody)
	}
	partof, err := strconv.ParseInt(ss[1], 10, 0)
	if err != nil || partof < 0 {
		return 0, len(n.RawBody)
	}
	if part >= partof {
		return 0, len(n.RawBody)
	}
	return int(part), int(partof)
}

// EncodeMultipart encodes a pair of integers for the multipart field.
func EncodeMultipart(part, partof int) string {
	return fmt.Sprintf("%d/%d", part, partof)
}

type chunk struct {
	offset int
	buf    []byte
}

func (c chunk) end() int {
	return c.offset + len(c.buf)
}

// Reassembler maintains state for a reassembled notice.
type Reassembler struct {
	length int
	// We maintain a list of chunks that are ordered and separated
	// by gaps. When completed, there is exactly one chunk. This
	// differs from the libzephyr strategy of allocating a buffer
	// ahead of time to be slightly less of a DoS vector.
	chunks     []chunk
	header     Header
	haveHeader bool
	// TODO(davidben): This is using libzephyr's behavior. After
	// this is working, experiment with just including the
	// AuthStatus into the key. The main concern is problems with
	// the zhm retransmit bug.
	authStatus AuthStatus
}

// NewReassembler creates a Reassembler for a message with a given
// body length.
func NewReassembler(length int) *Reassembler {
	return &Reassembler{length, []chunk{}, Header{}, false, AuthYes}
}

// NewReassemblerFromMultipartField creates a Reassembler for a given
// notice's multipart field. Note that this does not call AddNotice.
func NewReassemblerFromMultipartField(n *Notice) (*Reassembler, error) {
	_, partof := ParseMultipart(n)
	if partof > MaxMessageBodyLength {
		return nil, ErrBodyTooLong
	}
	return NewReassembler(partof), nil
}

// TODO(davidben): Add serialization/deserialization methods for crazy
// fault-tolerant Roost version.

// Done returns true when the message body has been reassembled.
func (r *Reassembler) Done() bool {
	if !r.haveHeader {
		return false
	}
	if r.length == 0 {
		return true
	}
	return len(r.chunks) == 1 && r.chunks[0].offset == 0 &&
		len(r.chunks[0].buf) == r.length
}

// Message returns the reassembled message once it is done.
func (r *Reassembler) Message() (*Message, AuthStatus) {
	if !r.Done() {
		return nil, AuthFailed
	}
	if r.length == 0 {
		return &Message{r.header, []string{""}}, r.authStatus
	}
	return &Message{r.header, strings.Split(string(r.chunks[0].buf), "\x00")}, r.authStatus
}

// AddNotice adds a notice into the reassembler state. If the notice
// is incompatible and discarded, it returns an error.
func (r *Reassembler) AddNotice(n *Notice, authStatus AuthStatus) error {
	if r.Done() {
		return nil
	}

	// Check if this notice is compatible.
	part, partof := ParseMultipart(n)
	if partof != r.length {
		return ErrBodyLengthMismatch
	}
	if part+len(n.RawBody) > r.length {
		return ErrBodyFragmentOutOfBounds
	}

	// Incorporate the AuthStatus.
	if authStatus == AuthFailed {
		r.authStatus = AuthFailed
	} else if authStatus == AuthNo && r.authStatus != AuthFailed {
		r.authStatus = AuthNo
	}

	// Copy the header over.
	if part == 0 {
		r.header = n.Header
		r.haveHeader = true
	}

	if len(n.RawBody) == 0 {
		return nil
	}

	// Fill in the new chunks. First we insert our new chunk in order.
	ordered := []chunk{}
	added := false
	for _, c := range r.chunks {
		if c.offset > part && !added {
			added = true
			ordered = append(ordered, chunk{part, n.RawBody})
		}
		ordered = append(ordered, c)
	}
	if !added {
		ordered = append(ordered, chunk{part, n.RawBody})
	}

	// Now collapse chunks that touch.
	dedup := []chunk{}
	for _, c := range ordered {
		if len(dedup) == 0 || dedup[len(dedup)-1].end() < c.offset {
			dedup = append(dedup, c)
		} else {
			// Merge c into last by appending the last n
			// bytes of c.
			last := dedup[len(dedup)-1]
			if n := c.end() - last.end(); n > 0 {
				dedup[len(dedup)-1] = chunk{
					last.offset,
					append(last.buf, c.buf[len(c.buf)-n:]...)}
			}
		}
	}
	r.chunks = dedup
	return nil
}
