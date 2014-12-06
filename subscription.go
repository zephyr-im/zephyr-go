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
	"time"

	"github.com/zephyr-im/krb5-go"
)

// WildcardInstance is the instance value used to subscribe to all
// instances for a given recipient, class pair.
const WildcardInstance = "*"

// A Subscription represents a triple to subscribe to.
type Subscription struct {
	Recipient string
	Class     string
	Instance  string
}

func tripleLength(s *Subscription) int {
	return len(s.Recipient) + len(s.Class) + len(s.Instance) + 3
}

const (
	clientSubscribe       = "SUBSCRIBE"
	clientSubscribeNoDefs = "SUBSCRIBE_NODEFS"
	clientUnsubscribe     = "UNSUBSCRIBE"
	clientCancelSub       = "CLEARSUB"
	clientGimmeSubs       = "GIMME"
	clientGimmeDefs       = "GIMMEDEFS"
	clientFlushSubs       = "FLUSHSUBS"
)

func sendControlNotice(ctx *krb5.Context, conn *Connection,
	port uint16, opcode string, subs []Subscription) (*Notice, error) {
	if port == 0 {
		port = uint16(conn.LocalAddr().Port)
	}

	uid := MakeUID(conn.LocalAddr().IP, time.Now())
	notice := &Notice{
		Header: Header{
			Kind:          ACKED,
			UID:           uid,
			Port:          port,
			Class:         "ZEPHYR_CTL",
			Instance:      "CLIENT",
			OpCode:        opcode,
			Sender:        conn.Credential().Client.String(),
			SenderAddress: conn.LocalAddr().IP,
		},
	}
	// Edge case: no subs to send. Still send at least one packet.
	if len(subs) == 0 {
		return conn.SendNotice(ctx, notice)
	}

	// Otherwise, this needs to be sharded. First, compute how
	// much space we have in the body.
	pkt, err := notice.EncodePacketForServer(ctx, conn.Credential())
	if err != nil {
		return nil, err
	}
	headerLen := len(pkt)

	var ack *Notice
	for len(subs) > 0 {
		// Compute how many triples will fit in one
		// packet. Leave some 13 bytes of slop because, if
		// we're unlucky, zcode may blow up the input. 13
		// chosen because it's what libzephyr uses and is
		// above 1024 / 128. See also: message.go.
		remaining := MaxPacketLength - headerLen - 13
		i := 0
		for ; i < len(subs); i++ {
			l := tripleLength(&subs[i])
			if l > remaining {
				break
			} else {
				remaining -= l
			}
		}

		if i == 0 {
			return nil, ErrPacketTooLong
		}

		shard := subs[0:i]
		subs = subs[i:]

		// Send this shard. Should end with a trailing NUL, so
		// add an empty field at the end.
		fields := make([][]byte, len(shard)*3+1)
		for j, sub := range shard {
			fields[3*j] = []byte(sub.Class)
			fields[3*j+1] = []byte(sub.Instance)
			fields[3*j+2] = []byte(sub.Recipient)
		}
		uid := MakeUID(conn.LocalAddr().IP, time.Now())
		notice.UID = uid
		notice.MultiUID = uid
		notice.RawBody = bytes.Join(fields, []byte{0})
		pkt, err := notice.EncodePacketForServer(ctx, conn.Credential())
		if err != nil {
			return nil, err
		}

		ack, err = conn.SendPacket(pkt, ACKED, uid)
		if err != nil {
			return nil, err
		} else if ack.Kind != SERVACK {
			return ack, nil
		}
	}

	// Return the last ACK we saw.
	return ack, nil
}

// SendSubscribe uses a connection to subscribe to a list of
// subscriptions, along with any defaults configured on the
// server. The passed krb5 context is used to authenticate the
// request. The port number is the port to subscribe, or 0 to use the
// port of the connection.
func SendSubscribe(
	ctx *krb5.Context,
	conn *Connection,
	port uint16,
	subs []Subscription,
) (*Notice, error) {
	return sendControlNotice(ctx, conn, port, clientSubscribe, subs)
}

// SendSubscribeNoDefaults uses a connection to subscribe to a list of
// subscriptions. The passed krb5 context is used to authenticate the
// request. The port number is the port to subscribe, or 0 to use the
// port of the connection.
func SendSubscribeNoDefaults(
	ctx *krb5.Context,
	conn *Connection,
	port uint16,
	subs []Subscription,
) (*Notice, error) {
	return sendControlNotice(ctx, conn, port, clientSubscribeNoDefs, subs)
}

// SendUnsubscribe uses a connection to unsubscribe from a list of
// subscriptions. The passed krb5 context is used to authenticate the
// request. The port number is the port to subscribe, or 0 to use the
// port of the connection.
func SendUnsubscribe(
	ctx *krb5.Context,
	conn *Connection,
	port uint16,
	subs []Subscription,
) (*Notice, error) {
	return sendControlNotice(ctx, conn, port, clientUnsubscribe, subs)
}

// SendCancelSubscriptions uses a connection to close a session. The
// passed krb5 context is used to authenticate the request. The port
// number is the port to subscribe, or 0 to use the port of the
// connection.
func SendCancelSubscriptions(
	ctx *krb5.Context,
	conn *Connection,
	port uint16,
) (*Notice, error) {
	return sendControlNotice(ctx, conn, port, clientCancelSub, nil)
}
