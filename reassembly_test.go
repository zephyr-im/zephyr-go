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
	"fmt"
	"reflect"
	"testing"
)

var longMessage []byte

func init() {
	longMessage = []byte{}
	for i := 0; i < 256; i++ {
		longMessage = append(longMessage, byte(i))
	}
}

func longMessageChunk(uid, multiuid UID, off, length int) *Notice {
	notice := sampleNoticeWithUID(uid)
	notice.MultiUID = multiuid
	notice.Multipart = fmt.Sprintf("%d/%d", off, len(longMessage))
	notice.RawBody = longMessage[off : off+length]
	return notice
}

func TestParseMultipart(t *testing.T) {
	length := len(sampleNotice().RawBody)
	tests := []struct {
		in     string
		part   int
		partof int
	}{
		{"0/10", 0, 10},
		{"4/5", 4, 5},
		{"-1/5", 0, length},
		{"bogus", 0, length},
		{"5", 0, length},
		{"10/5", 0, length},
		{"5/5", 0, length},
		{"bogus/5", 0, length},
		{"5/bogus", 0, length},
		{"5/-1", 0, length},
	}
	for i, tt := range tests {
		notice := sampleNotice()
		notice.Multipart = tt.in
		part, partof := ParseMultipart(notice)
		if part != tt.part || partof != tt.partof {
			t.Errorf("%d. ParseMultipart(%q) => %d %d, want %d %d",
				i, tt.in, part, partof, tt.part, tt.partof)
		}
	}
}

func TestReassembler(t *testing.T) {
	expected := sampleMessage(sampleNotice().UID, longMessage)

	type chunkTest struct {
		off    int
		length int
		auth   AuthStatus
	}
	tests := []struct {
		chunks []chunkTest
		auth   AuthStatus
	}{
		{[]chunkTest{{0, 256, AuthYes}}, AuthYes},
		{[]chunkTest{{0, 128, AuthYes}, {128, 128, AuthYes}}, AuthYes},
		{[]chunkTest{{128, 128, AuthYes}, {0, 128, AuthYes}}, AuthYes},
		{[]chunkTest{{100, 156, AuthYes}, {0, 128, AuthYes}}, AuthYes},
		{[]chunkTest{{0, 128, AuthYes}, {100, 156, AuthYes}}, AuthYes},
		{
			[]chunkTest{
				{0, 1, AuthYes}, {7, 1, AuthYes},
				{5, 1, AuthYes}, {3, 1, AuthYes},
				{0, 256, AuthYes},
			},
			AuthYes,
		},
		{
			[]chunkTest{
				{5, 0, AuthYes}, {0, 128, AuthYes},
				{128, 0, AuthYes}, {128, 128, AuthYes},
			},
			AuthYes,
		},
		{[]chunkTest{{0, 128, AuthYes}, {128, 128, AuthNo}}, AuthNo},
		{[]chunkTest{{0, 128, AuthNo}, {128, 128, AuthYes}}, AuthNo},
		{[]chunkTest{{0, 128, AuthNo}, {128, 128, AuthNo}}, AuthNo},
		{[]chunkTest{{0, 128, AuthYes}, {128, 128, AuthFailed}}, AuthFailed},
		{[]chunkTest{{0, 128, AuthFailed}, {128, 128, AuthYes}}, AuthFailed},
		{[]chunkTest{{0, 128, AuthNo}, {128, 128, AuthFailed}}, AuthFailed},
		{[]chunkTest{{0, 128, AuthFailed}, {128, 128, AuthNo}}, AuthFailed},
		{[]chunkTest{{0, 128, AuthFailed}, {128, 128, AuthFailed}}, AuthFailed},
	}
TestLoop:
	for i, tt := range tests {
		r := NewReassembler(len(longMessage))
		for _, c := range tt.chunks {
			if r.Done() {
				t.Errorf("%d. r.Done() was true; want false", i)
				continue TestLoop
			}

			// Make sure that the header comes from the
			// first packet.
			var uid UID
			multiuid := sampleNotice().UID
			if c.off == 0 {
				uid = multiuid
			}
			notice := longMessageChunk(uid, multiuid, c.off, c.length)
			if err := r.AddNotice(notice, c.auth); err != nil {
				t.Errorf("%d. r.AddNotice(chunk %d, %d) failed: %v",
					i, c.off, c.off+c.length, err)
				continue TestLoop
			}
		}
		if !r.Done() {
			t.Errorf("%d. r.Done() was false; want true", i)
			continue TestLoop
		}
		m, auth := r.Message()
		expectHeadersEqual(t, &m.Header, &expected.Header)
		if !reflect.DeepEqual(m.Body, expected.Body) {
			t.Errorf("%d. m.Body = %v; want %v", i, m.Body, expected.Body)
		}
		if auth != tt.auth {
			t.Errorf("auth = %v; want %v", auth, tt.auth)
		}
	}
}

func TestReassemblerLengthMismatch(t *testing.T) {
	r := NewReassembler(5)
	if err := r.AddNotice(sampleNotice(), AuthYes); err != ErrBodyLengthMismatch {
		t.Errorf("r.AddNotice did not fail as expected: %v", err)
	}
}

func TestReassemblerOutOfBounds(t *testing.T) {
	r := NewReassembler(5)
	notice := sampleNotice()
	notice.RawBody = []byte("1234567890")
	notice.Multipart = "0/5"
	if err := r.AddNotice(notice, AuthYes); err != ErrBodyFragmentOutOfBounds {
		t.Errorf("r.AddNotice did not fail as expected: %v", err)
	}
}

func TestReassemblerMaxBodyLength(t *testing.T) {
	notice := sampleNotice()
	notice.Multipart = "0/500000"
	if _, err := NewReassemblerFromMultipartField(notice); err != ErrBodyTooLong {
		t.Errorf("NewReassemblerFromMultipartField did not fail as expected: %v", err)
	}
}

func TestReassemblerZeroLength(t *testing.T) {
	r := NewReassembler(0)
	if r.Done() {
		t.Errorf("r.Done() = true; want false")
	}
	notice := sampleNotice()
	notice.RawBody = []byte{}
	notice.Multipart = "0/0"
	if err := r.AddNotice(notice, AuthYes); err != nil {
		t.Errorf("r.AddNotice failed: %v", err)
	}
	if !r.Done() {
		t.Errorf("r.Done() = false; want true")
	}
	m, auth := r.Message()
	expectHeadersEqual(t, &m.Header, &sampleNotice().Header)
	if len(m.Body) != 1 || m.Body[0] != "" {
		t.Errorf("m.Body = %v; want []", m.Body)
	}
	if auth != AuthYes {
		t.Errorf("auth = %v; want AuthYes", auth)
	}
}
