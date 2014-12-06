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
	"strings"
	"time"

	"github.com/zephyr-im/krb5-go"
)

// A Message is a high-level reassembled zepyr message. This is the
// final stage of the messaging pipeline.
type Message struct {
	Header
	Body []string
}

func sendMessage(conn *Connection, msg *Message, slop int,
	encodeFn func(*Notice) ([]byte, error)) (*Notice, error) {
	// Determine the body to send.
	rawBody := []byte(strings.Join(msg.Body, "\x00"))
	rawBodyLen := len(rawBody)

	// Special-case: if the body is empty, send one packet.
	if rawBodyLen == 0 {
		notice := &Notice{
			Header:    msg.Header,
			MultiUID:  msg.UID,
			Multipart: "0/0",
		}
		pkt, err := encodeFn(notice)
		if err != nil {
			return nil, err
		}
		return conn.SendPacket(pkt, notice.Kind, notice.UID)
	}

	// First, compute how much space we have for the body.
	notice := &Notice{Header: msg.Header, MultiUID: msg.UID}
	var headerLen int
	pkt, err := encodeFn(notice)
	if err != nil {
		return nil, err
	}
	headerLen = len(pkt)

	var ack *Notice
	uid := msg.UID
	offset := 0
	for len(rawBody) != 0 {
		// Compute multipart field.
		multipart := EncodeMultipart(offset, rawBodyLen)
		// Put as much of the body in as we can.
		remaining := MaxPacketLength - headerLen - len(multipart) - slop
		if len(rawBody) < remaining {
			remaining = len(rawBody)
		}
		// The header was too long to include the body.
		if remaining <= 0 {
			return nil, ErrPacketTooLong
		}

		// Prepare the next notice.
		notice.UID = uid
		notice.Multipart = multipart
		notice.RawBody = rawBody[:remaining]
		pkt, err := encodeFn(notice)
		if err != nil {
			return nil, err
		}

		// Send the notice. Stop on error or SERVNAK. (The
		// notice might not be ACKED, so it's possible for ack
		// to be nil.)
		ack, err = conn.SendPacket(pkt, notice.Kind, notice.UID)
		if err != nil {
			return nil, err
		} else if ack != nil && ack.Kind != SERVACK {
			return ack, nil
		}

		// Next packet gets a new uid.
		uid = MakeUID(conn.LocalAddr().IP, time.Now())
		rawBody = rawBody[remaining:]
		offset += remaining
	}

	// Return the last ACK we saw.
	return ack, nil
}

// SendMessage sends an authenticated message across a connection,
// sharding into multiple notices as needed. It returns the ACK from
// the server if the message is ACKED.
func SendMessage(ctx *krb5.Context, conn *Connection, msg *Message) (*Notice, error) {
	// Leave some 13 bytes of slop because, if we're unlucky,
	// zcode may blow up the input. 13 was chosen because it's
	// what libzephyr uses and is above 1024 / 128.
	return sendMessage(conn, msg, 13, func(n *Notice) ([]byte, error) {
		return n.EncodePacketForServer(ctx, conn.Credential())
	})
}

// SendMessageUnauth sends an unauthenticated message across a
// connection, sharding into multiple notices as needed. It returns
// the ACK from the server if the message is ACKED.
func SendMessageUnauth(conn *Connection, msg *Message) (*Notice, error) {
	// No slop needed because there isn't a checksum in this notice.
	return sendMessage(conn, msg, 0, func(n *Notice) ([]byte, error) {
		return n.EncodePacketUnauth(), nil
	})
}
