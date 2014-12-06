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
	"log"
	"net"
	"time"

	"github.com/zephyr-im/krb5-go"
)

const dedupLifetime = 900 * time.Second
const fragmentLifetime = 30 * time.Second

// A MessageReaderResult is an output of a Session's incoming Message
// channel. It either contains a Message with accompanying AuthStatus
// or an error.
type MessageReaderResult struct {
	Message    *Message
	AuthStatus AuthStatus
}

// A Session is a high-level connection to the zephyr servers. It
// handles reassembly of sharded messages, ACKs, and deduplicating
// notices by UID. This API should be used by most zephyr clients.
type Session struct {
	conn     *Connection
	logger   *log.Logger
	clock    Clock
	messages chan MessageReaderResult
}

// NewSession creates a new Session attached to a given connection
// with server configuration and credential.
func NewSession(
	conn net.PacketConn,
	server ServerConfig,
	cred *krb5.Credential,
	logger *log.Logger,
) (*Session, error) {
	return NewSessionFull(conn, server, cred, logger, SystemClock)
}

// NewSessionFull creates a new Session attached to a given connection
// with server configuration and credential. This variant allows
// passing a custom clock for testing.
func NewSessionFull(
	conn net.PacketConn,
	server ServerConfig,
	cred *krb5.Credential,
	logger *log.Logger,
	clock Clock,
) (*Session, error) {
	zconn, err := NewConnectionFull(conn, server, cred, logger, clock)
	if err != nil {
		return nil, err
	}

	s := &Session{zconn, logger, clock, make(chan MessageReaderResult)}
	go s.noticeLoop()
	return s, nil
}

func (s *Session) noticeLoop() {
	dedup := NewWindowedMapFull(dedupLifetime, s.clock)
	reassemble := NewWindowedMapFull(fragmentLifetime, s.clock)

	for r := range s.conn.Notices() {
		// ACK if appropriate.
		if r.Notice.Kind.ExpectsClientACK() {
			s.conn.SendNoticeUnackedTo(
				r.Notice.MakeACK(CLIENTACK, ""), r.Addr)
		}

		// Deduplicate.
		if _, ok := dedup.Lookup(r.Notice.UID); ok {
			continue
		}
		dedup.Put(r.Notice.UID, nil)

		// Reassemble.
		var msg *Reassembler
		if t, ok := reassemble.Lookup(r.Notice.MultiUID); ok {
			msg = t.(*Reassembler)
		} else {
			var err error
			msg, err = NewReassemblerFromMultipartField(r.Notice)
			if err != nil {
				logPrintf(s.logger, "Error parsing multipart: %v", err)
				continue
			}
			reassemble.Put(r.Notice.MultiUID, msg)
		}
		if err := msg.AddNotice(r.Notice, r.AuthStatus); err != nil {
			logPrintf(s.logger, "Error reassembling notice: %v", err)
			continue
		}
		if msg.Done() {
			reassemble.Remove(r.Notice.MultiUID)
			m, a := msg.Message()
			s.messages <- MessageReaderResult{m, a}
		}
	}
	close(s.messages)
}

// Messages returns the incoming messages from the session.
func (s *Session) Messages() <-chan MessageReaderResult {
	return s.messages
}

// LocalAddr returns the local UDP address for the client when
// communicating with the Zephyr servers.
func (s *Session) LocalAddr() *net.UDPAddr {
	return s.conn.LocalAddr()
}

// Port returns the local UDP port for the client.
func (s *Session) Port() uint16 {
	return uint16(s.conn.LocalAddr().Port)
}

// Credential returns the credential for this session.
func (s *Session) Credential() *krb5.Credential {
	return s.conn.Credential()
}

// Sender returns the user the session is authenticated as.
func (s *Session) Sender() string {
	return s.Credential().Client.String()
}

// Realm returns the realm of the server being connected to.
func (s *Session) Realm() string {
	// TODO(davidben): This really should come from the server
	// config or something.
	return s.Credential().Server.Realm
}

// Close closes the session.
func (s *Session) Close() error {
	return s.conn.Close()
}

// MakeUID creates a new UID for a given time and this sessions local
// IP address.
func (s *Session) MakeUID(t time.Time) UID {
	return MakeUID(s.LocalAddr().IP, t)
}

// SendSubscribe sends a subscription notice for a list of triples,
// along with any defaults configured on the server.
func (s *Session) SendSubscribe(
	ctx *krb5.Context,
	subs []Subscription,
) (*Notice, error) {
	return SendSubscribe(ctx, s.conn, 0, subs)
}

// SendSubscribeNoDefaults sends a subscription notice for a list of
// triples. It returns the ACK from the server.
func (s *Session) SendSubscribeNoDefaults(
	ctx *krb5.Context,
	subs []Subscription,
) (*Notice, error) {
	return SendSubscribeNoDefaults(ctx, s.conn, 0, subs)
}

// SendUnsubscribe unsubscribes from a list of triples. It returns the
// ACK from the server.
func (s *Session) SendUnsubscribe(
	ctx *krb5.Context,
	subs []Subscription,
) (*Notice, error) {
	return SendUnsubscribe(ctx, s.conn, 0, subs)
}

// SendCancelSubscriptions closes the session. This should be called
// before exit to release the port on the zephyrd. It returns the ACK
// from the server.
func (s *Session) SendCancelSubscriptions(ctx *krb5.Context) (*Notice, error) {
	return SendCancelSubscriptions(ctx, s.conn, 0)
}

// SendMessage sends an authenticated message over the session,
// sharding into multiple notices as needed. It returns the ACK from
// the server if the message is ACKED.
func (s *Session) SendMessage(ctx *krb5.Context, msg *Message) (*Notice, error) {
	return SendMessage(ctx, s.conn, msg)
}

// SendMessageUnauth sends an unauthenticated message over the
// session, sharding into multiple notices as needed. It returns the
// ACK from the server if the message is ACKED.
func (s *Session) SendMessageUnauth(msg *Message) (*Notice, error) {
	return SendMessageUnauth(s.conn, msg)
}
