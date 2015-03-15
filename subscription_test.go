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
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/zephyr-im/krb5-go"
	"github.com/zephyr-im/krb5-go/krb5test"
	"github.com/zephyr-im/zephyr-go/zephyrtest"
)

func ackAndDumpNotices(t *testing.T, conn net.PacketConn, auth AuthStatus, sink chan<- *Notice) {
	ctx, keytab := makeServerContextAndKeyTab(t)
	defer ctx.Free()
	defer keytab.Close()
	for r := range ReadRawNotices(conn) {
		authStatus, _, err := r.RawNotice.CheckAuthFromClient(
			ctx, krb5test.Service(), keytab)
		if err != nil {
			t.Fatalf("CheckAuthFromClient failed: %v", err)
			return
		}
		notice, err := DecodeRawNotice(r.RawNotice)
		if err != nil {
			t.Fatalf("DecodeRawNotice failed: %v", err)
			return
		}
		if authStatus != auth {
			t.Errorf("Bad authStatus %v; want %v", authStatus, auth)
		}
		if notice.Kind.ExpectsServerACK() {
			conn.WriteTo(notice.MakeACK(SERVACK, "SENT").EncodePacketUnauth(),
				r.Addr)
		}
		sink <- notice
	}
	close(sink)
}

func nackNotices(t *testing.T, conn net.PacketConn) {
	for r := range ReadRawNotices(conn) {
		notice, err := DecodeRawNotice(r.RawNotice)
		if err != nil {
			t.Fatalf("DecodeRawNotice failed: %v", err)
			return
		}
		if notice.Kind.ExpectsServerACK() {
			conn.WriteTo(notice.MakeACK(SERVNAK, "LOST").EncodePacketUnauth(),
				r.Addr)
		}
	}
}

func checkSubscriptionNotice(
	t *testing.T, n *Notice, port uint16, opcode string) []Subscription {
	if n.Kind != ACKED {
		t.Errorf("n.Kind = %v; want ACKED", n.Kind)
	}
	if n.Port != port {
		t.Errorf("n.Port = %v; want %v", n.Port, port)
	}
	if n.Class != "ZEPHYR_CTL" {
		t.Errorf("n.Class = %q; want 'ZEPHYR_CTL'", n.Class)
	}
	if n.Instance != "CLIENT" {
		t.Errorf("n.Instance = %q; want 'CLIENT'", n.Instance)
	}
	if n.OpCode != opcode {
		t.Errorf("n.OpCode = %q; want %q", n.OpCode, opcode)
	}
	chunks := bytes.Split(n.RawBody, []byte{0})
	if len(chunks) == 0 {
		t.Errorf("chunks is empty.")
		return nil
	}
	if len(chunks[len(chunks)-1]) != 0 {
		t.Errorf("End of chunks should be empty.")
		return nil
	}
	chunks = chunks[0 : len(chunks)-1]
	if len(chunks)%3 != 0 {
		t.Errorf("Body length not a multiple of 3: %d", len(chunks))
		return nil
	}
	out := []Subscription{}
	for i := 0; i+2 < len(chunks); i += 3 {
		out = append(out, Subscription{
			Recipient: string(chunks[i+2]),
			Class:     string(chunks[i]),
			Instance:  string(chunks[i+1]),
		})
	}
	return out
}

func TestSendSubscribe(t *testing.T) {
	tests := [][]Subscription{
		// Basic case.
		[]Subscription{
			{"", "davidben", WildcardInstance},
			{"davidben@ATHENA.MIT.EDU", "message", "personal"},
		},
		// Empty subs list.
		[]Subscription{},
	}
	// Too many subs.
	long := []Subscription{}
	for i := 0; i < 1000; i++ {
		long = append(long, Subscription{
			"", fmt.Sprintf("class%d", i), WildcardInstance})
	}
	tests = append(tests, long)

	for i, subs := range tests {
		ctx, err := krb5.NewContext()
		if err != nil {
			t.Fatal(err)
		}
		defer ctx.Free()

		clock := zephyrtest.NewMockClock()
		client, server := mockNetwork1()
		conn, err := NewConnectionFull(client, serverConfig,
			krb5test.Credential(), clock)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		// Set up a "server" to SERVACK notices as they come in.
		notices := make(chan *Notice, len(subs))
		go ackAndDumpNotices(t, server, AuthYes, notices)

		ack, err := SendSubscribeNoDefaults(ctx, conn, 0, subs)
		if err != nil {
			t.Fatalf("[%d] SendSubscribeNoDefaults failed: %v", i, err)
		}
		if ack.Kind != SERVACK {
			t.Errorf("[%d] ack.Kind = %v; want SERVACK", i, ack.Kind)
		}
		if string(ack.RawBody) != "SENT" {
			t.Errorf("[%d] ack.RawBody = %v; want 'SENT'",
				i, string(ack.RawBody))
		}
		server.Close()

		// Find out what was sent.
		sentSubs := []Subscription{}
		gotNotice := false
		for notice := range notices {
			gotNotice = true
			s := checkSubscriptionNotice(t, notice,
				uint16(conn.LocalAddr().Port),
				clientSubscribeNoDefs)
			sentSubs = append(sentSubs, s...)
		}
		if !reflect.DeepEqual(sentSubs, subs) {
			t.Errorf("[%d] Sent %v; want %v", i, sentSubs, subs)
		}
		if !gotNotice {
			t.Errorf("Received no notices")
		}
	}
}

func TestSendSubscribeTooLong(t *testing.T) {
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()

	clock := zephyrtest.NewMockClock()
	client, server := mockNetwork1()
	defer server.Close()
	conn, err := NewConnectionFull(client, serverConfig,
		krb5test.Credential(), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	class := ""
	for i := 0; i < MaxPacketLength; i++ {
		class += "z"
	}
	subs := []Subscription{{"", class, WildcardInstance}}
	_, err = SendSubscribeNoDefaults(ctx, conn, 0, subs)
	if err != ErrPacketTooLong {
		t.Fatalf("SendSubscribeNoDefaults didn't fail as expected: %v", err)
	}
}

func TestSendSubscribeNack(t *testing.T) {
	subs := []Subscription{
		{"", "davidben", WildcardInstance},
		{"davidben@ATHENA.MIT.EDU", "message", "personal"},
	}

	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()

	clock := zephyrtest.NewMockClock()
	client, server := mockNetwork1()
	defer server.Close()
	conn, err := NewConnectionFull(client, serverConfig,
		krb5test.Credential(), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Set up a "server" to SERVNAK notices as they come in.
	go nackNotices(t, server)

	ack, err := SendSubscribeNoDefaults(ctx, conn, 0, subs)
	if err != nil {
		t.Fatalf("SendSubscribeNoDefaults failed: %v", err)
	}
	if ack.Kind != SERVNAK {
		t.Errorf("ack.Kind = %v; want SERVNAK", ack.Kind)
	}
	if string(ack.RawBody) != "LOST" {
		t.Errorf("ack.RawBody = %v; want 'LOST'", string(ack.RawBody))
	}
}

func TestSendSubscribeSendError(t *testing.T) {
	subs := []Subscription{
		{"", "davidben", WildcardInstance},
		{"davidben@ATHENA.MIT.EDU", "message", "personal"},
	}

	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()

	clock := zephyrtest.NewMockClock()
	readChan := make(chan zephyrtest.PacketRead)
	close(readChan)
	mock := zephyrtest.NewMockPacketConn(clientAddr, readChan)
	conn, err := NewConnectionFull(mock, serverConfig,
		krb5test.Credential(), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Set up a "server" to fail all writes.
	expectedErr := errors.New("failed")
	go func() {
		for write := range mock.Writes() {
			write.Result <- expectedErr
		}
	}()

	// Send the message.
	if _, err := SendSubscribeNoDefaults(ctx, conn, 0, subs); err != expectedErr {
		t.Errorf("SendMessageUnauth didn't fail as expected: %v", err)
	}
}
