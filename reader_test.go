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
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"reflect"
	"testing"

	"github.com/zephyr-im/krb5-go"
	"github.com/zephyr-im/zephyr-go/zephyrtest"
)

func newTestLogger() (*log.Logger, io.Closer, <-chan string) {
	pr, pw := io.Pipe()
	l := log.New(pw, "", 0)
	c := make(chan string)
	go func() {
		s := bufio.NewScanner(pr)
		for s.Scan() {
			c <- s.Text()
		}
		// Meh.
		if err := s.Err(); err != nil {
			c <- "Error scanning: " + err.Error()
		}
		close(c)
	}()
	return l, pw, c
}

func expectNoLogs(t *testing.T) (*log.Logger, io.Closer) {
	l, closer, c := newTestLogger()
	go func() {
		for line := range c {
			t.Error(line)
		}
	}()
	return l, closer
}

func TestReadNoticesFromServer(t *testing.T) {
	addr1 := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 1111}
	addr2 := &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 2222}
	clientAddr := &net.UDPAddr{IP: net.IPv4(3, 3, 3, 3), Port: 3333}
	fatalErr := errors.New("polarity insufficiently reversed")

	type resultOrErr struct {
		r    *NoticeReaderResult
		line string
	}
	result := func(n *Notice, as AuthStatus, addr net.Addr) resultOrErr {
		return resultOrErr{r: &NoticeReaderResult{n, as, addr}}
	}
	err := func(line string) resultOrErr {
		return resultOrErr{line: line}
	}

	type test struct {
		keyblock *krb5.KeyBlock
		reads    []zephyrtest.PacketRead
		expected []resultOrErr
	}
	tests := []test{
		// Basic case
		{
			sampleKeyBlock(),
			[]zephyrtest.PacketRead{
				{samplePacket(), addr1, nil},
			}, []resultOrErr{
				result(sampleNotice(), AuthYes, addr1),
			},
		},
		// Various non-fatal errors.
		{
			sampleKeyBlock(),
			[]zephyrtest.PacketRead{
				{nil, nil, zephyrtest.TemporaryError},
				{samplePacket(), addr1, nil},
				{nil, nil, zephyrtest.TemporaryError},
				{nil, nil, zephyrtest.TemporaryError},
				{samplePacket(), addr2, nil},
				{sampleFailPacket(), addr1, nil},
				{sampleMalformedChecksumPacket(), addr2, nil},
				{sampleMalformedPortPacket(), addr1, nil},
				{[]byte("bogus"), addr2, nil},
				{samplePacket(), addr1, nil},
			},
			[]resultOrErr{
				err("Error reading packet: Temporary error"),
				result(sampleNotice(), AuthYes, addr1),
				err("Error reading packet: Temporary error"),
				err("Error reading packet: Temporary error"),
				// samplePacket
				result(sampleNotice(), AuthYes, addr2),
				// sampleFailPacket
				result(sampleNotice(), AuthFailed, addr1),
				// sampleMalformedChecksumPacket
				err("Error authenticating notice: invalid zcode"),
				result(sampleNotice(), AuthFailed, addr2),
				// sampleMalformedPortPacket
				err("Error parsing notice: bad length for " +
					"uint16 zephyrascii"),
				// bogus
				err("Error decoding notice: bad packet format"),
				// samplePacket
				result(sampleNotice(), AuthYes, addr1),
			},
		},
		// Stop after fatal error.
		{
			sampleKeyBlock(),
			[]zephyrtest.PacketRead{
				{nil, nil, fatalErr},
				{samplePacket(), addr1, nil},
			},
			[]resultOrErr{
				err("Error reading packet: polarity " +
					"insufficiently reversed"),
			},
		},
		// nil key.
		{
			nil,
			[]zephyrtest.PacketRead{
				{samplePacket(), addr1, nil},
			}, []resultOrErr{
				result(sampleNotice(), AuthFailed, addr1),
			},
		},
	}
	for ti, test := range tests {
		// Buffer of 1 because one of the tests intentionally
		// has an extra read.
		readChan := make(chan zephyrtest.PacketRead, 1)
		go func() {
			for _, read := range test.reads {
				readChan <- read
			}
			close(readChan)
		}()
		mock := zephyrtest.NewMockPacketConn(clientAddr, readChan)
		l, closer, lines := newTestLogger()
		out := ReadNoticesFromServer(mock, test.keyblock, l)
		for ei, expect := range test.expected {
			if expect.r != nil {
				if r, ok := <-out; !ok {
					t.Errorf("%d.%d. Expected notice: %v",
						ti, ei, expect.r)
				} else {
					expectNoticesEqual(t, r.Notice, expect.r.Notice)
					if r.AuthStatus != expect.r.AuthStatus {
						t.Errorf("%d.%d. AuthStatus = %v; want %v",
							ti, ei,
							r.AuthStatus,
							expect.r.AuthStatus)
					}
					if !reflect.DeepEqual(r.Addr, expect.r.Addr) {
						t.Errorf("%d.%d. Addr = %v; want %v",
							ti, ei,
							r.Addr,
							expect.r.Addr)
					}
				}
			} else {
				if line, ok := <-lines; !ok {
					t.Errorf("%d.%d. Expected error: %v",
						ti, ei, expect.line)
				} else if line != expect.line {
					t.Errorf("%d.%d. line = %v; wanted %v",
						ti, ei, line, expect.line)
				}
			}
		}
		closer.Close()
		for line := range lines {
			t.Errorf("%d. unexpected line: %v", ti, line)
		}
		for r := range out {
			t.Errorf("%d. unexpected notice: %v", ti, r)
		}
	}
}
