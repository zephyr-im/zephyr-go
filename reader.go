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
	"io"
	"log"
	"net"
	"time"

	"github.com/zephyr-im/krb5-go"
)

// MaxPacketLength is the maximum size of a zephyr notice on the wire.
const MaxPacketLength = 1024

// A RawReaderResult is an output of a ReadRawNotices call. It either
// contains a RawNotice and a source address or an error.
type RawReaderResult struct {
	RawNotice *RawNotice
	Addr      net.Addr
}

// ReadRawNotices decodes packets from a PacketConn into RawNotices
// and returns a stream of them. Non-fatal errors are returned through
// the stream. On a fatal error or EOF, the channel is closed.
func ReadRawNotices(conn net.PacketConn, logger *log.Logger) <-chan RawReaderResult {
	sink := make(chan RawReaderResult)
	go readRawNoticeLoop(conn, logger, sink)
	return sink
}

func readRawNoticeLoop(
	conn net.PacketConn,
	logger *log.Logger,
	sink chan<- RawReaderResult,
) {
	defer close(sink)
	var buf [MaxPacketLength]byte
	var tempDelay time.Duration
	for {
		n, addr, err := conn.ReadFrom(buf[:])
		if err != nil {
			// Send the error out to the consumer.
			if err != io.EOF {
				logPrintf(logger, "Error reading packet: %v\n", err)
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				// Delay logic from net/http.Serve.
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			break
		}
		tempDelay = 0

		// Copy the packet so we can reuse the buffer.
		raw, err := DecodePacket(copyByteSlice(buf[0:n]))
		if err != nil {
			logPrintf(logger, "Error decoding notice: %v\n", err)
			continue
		}
		sink <- RawReaderResult{raw, addr}
	}
}

// A NoticeReaderResult is an output of a ReadNoticesFromServer
// call. It either contains a notice with authentication status and
// source address or an error.
type NoticeReaderResult struct {
	Notice     *Notice
	AuthStatus AuthStatus
	Addr       net.Addr
}

// ReadNoticesFromServer decodes and authenticates notices sent from
// the server. Returns a channel containing authenticated notices and
// errors. The channel is closed on fatal errors. If key is nil, all
// notices appear as AuthFailed.
func ReadNoticesFromServer(
	conn net.PacketConn,
	key *krb5.KeyBlock,
	logger *log.Logger,
) <-chan NoticeReaderResult {
	// TODO(davidben): Should this channel be buffered a little?
	sink := make(chan NoticeReaderResult)
	go readNoticeLoop(ReadRawNotices(conn, logger), key, logger, sink)
	return sink
}

func readNoticeLoop(
	rawReader <-chan RawReaderResult,
	key *krb5.KeyBlock,
	logger *log.Logger,
	sink chan<- NoticeReaderResult,
) {
	defer close(sink)
	ctx, err := krb5.NewContext()
	if err != nil {
		logPrintf(logger, "Error creating krb5 context: %v", err)
		return
	}
	defer ctx.Free()
	for r := range rawReader {
		notice, err := DecodeRawNotice(r.RawNotice)
		if err != nil {
			logPrintf(logger, "Error parsing notice: %v", err)
			continue
		}

		authStatus := AuthFailed
		if notice.Kind.IsACK() {
			// Don't bother; ACKs' auth bits are always lies.
			authStatus = AuthNo
		} else if key != nil {
			authStatus, err = r.RawNotice.CheckAuthFromServer(ctx, key)
			if err != nil {
				logPrintf(logger, "Error authenticating notice: %v", err)
				authStatus = AuthFailed
			}
		}
		sink <- NoticeReaderResult{notice, authStatus, r.Addr}
	}
}
