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
	"io/ioutil"
	"log"
	"net"
	"os"
	"reflect"
	"testing"

	"github.com/zephyr-im/krb5-go"
	"github.com/zephyr-im/zephyr-go/zephyrtest"
)

func TestReadNoticesFromServer(t *testing.T) {
	// This test is noisy.
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	addr1 := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 1111}
	addr2 := &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 2222}
	clientAddr := &net.UDPAddr{IP: net.IPv4(3, 3, 3, 3), Port: 3333}
	fatalErr := errors.New("polarity insufficiently reversed")

	type test struct {
		keyblock *krb5.KeyBlock
		reads    []zephyrtest.PacketRead
		expected []*NoticeReaderResult
	}
	tests := []test{
		// Basic case
		{
			sampleKeyBlock(),
			[]zephyrtest.PacketRead{
				{samplePacket(), addr1, nil},
			}, []*NoticeReaderResult{
				{sampleNotice(), AuthYes, addr1},
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
			[]*NoticeReaderResult{
				// samplePacket
				{sampleNotice(), AuthYes, addr1},
				// samplePacket
				{sampleNotice(), AuthYes, addr2},
				// sampleFailPacket
				{sampleNotice(), AuthFailed, addr1},
				// sampleMalformedChecksumPacket
				{sampleNotice(), AuthFailed, addr2},
				// sampleMalformedPortPacket and bogus are dropped.
				// samplePacket
				{sampleNotice(), AuthYes, addr1},
			},
		},
		// Stop after fatal error.
		{
			sampleKeyBlock(),
			[]zephyrtest.PacketRead{
				{nil, nil, fatalErr},
				{samplePacket(), addr1, nil},
			},
			[]*NoticeReaderResult{},
		},
		// nil key.
		{
			nil,
			[]zephyrtest.PacketRead{
				{samplePacket(), addr1, nil},
			}, []*NoticeReaderResult{
				{sampleNotice(), AuthFailed, addr1},
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
		out := ReadNoticesFromServer(mock, test.keyblock)
		for ei, expect := range test.expected {
			if r, ok := <-out; !ok {
				t.Errorf("%d.%d. Expected notice: %v",
					ti, ei, expect)
			} else {
				expectNoticesEqual(t, r.Notice, expect.Notice)
				if r.AuthStatus != expect.AuthStatus {
					t.Errorf("%d.%d. AuthStatus = %v; want %v",
						ti, ei,
						r.AuthStatus,
						expect.AuthStatus)
				}
				if !reflect.DeepEqual(r.Addr, expect.Addr) {
					t.Errorf("%d.%d. Addr = %v; want %v",
						ti, ei,
						r.Addr,
						expect.Addr)
				}
			}
		}
		for r := range out {
			t.Errorf("%d. unexpected notice: %v", ti, r)
		}
	}
}
