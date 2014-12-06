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
	"reflect"
	"strings"
	"testing"

	"github.com/zephyr-im/krb5-go"
	"github.com/zephyr-im/krb5-go/krb5test"
	"github.com/zephyr-im/zephyr-go/zephyrtest"
)

func testSendMessage(t *testing.T, l int, auth AuthStatus) {
	hdr := fmt.Sprintf("(%d, %v)", l, auth)

	b := []byte{}
	for i := 0; i < l; i++ {
		b = append(b, byte(i))
	}
	body := strings.Split(string(b), "\x00")

	msg := &Message{sampleNotice().Header, body}

	logger, lc := expectNoLogs(t)
	defer lc.Close()
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Error(err)
		return
	}
	defer ctx.Free()

	clock := zephyrtest.NewMockClock()
	client, server := mockNetwork1()
	conn, err := NewConnectionFull(client, serverConfig,
		krb5test.Credential(), logger, clock)
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()

	// Set up a "server" to SERVACK notices as they come in.
	notices := make(chan *Notice, l+1)
	go ackAndDumpNotices(t, server, auth, notices)

	// Send the message.
	var ack *Notice
	if auth == AuthYes {
		ack, err = SendMessage(ctx, conn, msg)
	} else {
		ack, err = SendMessageUnauth(conn, msg)
	}
	server.Close()

	// Check the ACK and whatnot.
	if err != nil {
		t.Errorf("%s Error sending message: %v", hdr, err)
		return
	}
	if ack.Kind != SERVACK {
		t.Errorf("%s Received %v; want SERVACK", hdr, ack)
	}

	r := NewReassembler(l)
	for n := range notices {
		if !n.MultiUID.Equal(msg.UID) {
			t.Errorf("%s n.MultiUID = %v; want %v",
				hdr, n.MultiUID, msg.UID)
		}
		if r.Done() {
			t.Errorf("%s r.Done() = true; want false", hdr)
		}
		if err := r.AddNotice(n, AuthYes); err != nil {
			t.Errorf("%s r.AddNotice(n) failed: %v", hdr, err)
		}
	}
	if !r.Done() {
		t.Errorf("%s r.Done() = false; want true", hdr)
		return
	}
	m, _ := r.Message()
	expectHeadersEqual(t, &m.Header, &msg.Header)
	if !reflect.DeepEqual(m.Body, msg.Body) {
		t.Errorf("%s m.Body = %v; want %v", hdr, m.Body, msg.Body)
	}
}

func TestSendMessage(t *testing.T) {
	// Test 0 and all powers of 2.
	ls := []int{
		0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024,
		2048, 4096, 8192, 16384,
	}
	as := []AuthStatus{AuthYes, AuthNo}
	for _, l := range ls {
		for _, a := range as {
			testSendMessage(t, l, a)
		}
	}
}

func TestSendMessageLongHeader(t *testing.T) {
	l, lc := expectNoLogs(t)
	defer lc.Close()
	clock := zephyrtest.NewMockClock()
	client, server := mockNetwork1()
	defer server.Close()
	conn, err := NewConnectionFull(client, serverConfig,
		krb5test.Credential(), l, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := &Message{sampleNotice().Header, []string{"moo"}}
	msg.Class = "a"
	for i := 0; i < 1000; i++ {
		msg.Class += "-really"
	}
	msg.Class += "-long-class"

	_, err = SendMessageUnauth(conn, msg)
	if err != ErrPacketTooLong {
		t.Errorf("SendMessageUnauth(conn, msg) did not fail as expected: %v", err)
	}
}

func TestSendMessageNack(t *testing.T) {
	l, lc := expectNoLogs(t)
	defer lc.Close()
	clock := zephyrtest.NewMockClock()
	client, server := mockNetwork1()
	defer server.Close()
	conn, err := NewConnectionFull(client, serverConfig,
		krb5test.Credential(), l, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Set up a "server" to SERVNAK notices as they come in.
	go nackNotices(t, server)

	// Send the message.
	msg := &Message{sampleNotice().Header, []string{"moo"}}
	ack, err := SendMessageUnauth(conn, msg)

	// Check the ACK and whatnot.
	if err != nil {
		t.Fatalf("Error sending message: %v", err)
	}
	if ack.Kind != SERVNAK {
		t.Errorf("ack.Kind = %v; want SERVNAK", ack.Kind)
	}
	if string(ack.RawBody) != "LOST" {
		t.Errorf("ack.RawBody = %v; want 'LOST'", string(ack.RawBody))
	}
}

func TestSendMessageSendError(t *testing.T) {
	l, lc := expectNoLogs(t)
	defer lc.Close()
	clock := zephyrtest.NewMockClock()
	readChan := make(chan zephyrtest.PacketRead)
	close(readChan)
	mock := zephyrtest.NewMockPacketConn(clientAddr, readChan)
	conn, err := NewConnectionFull(mock, serverConfig,
		krb5test.Credential(), l, clock)
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
	msg := &Message{sampleNotice().Header, []string{"moo"}}
	if _, err := SendMessageUnauth(conn, msg); err != expectedErr {
		t.Errorf("SendMessageUnauth didn't fail as expected: %v", err)
	}
}
