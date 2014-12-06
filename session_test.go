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
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/zephyr-im/krb5-go"
	"github.com/zephyr-im/krb5-go/krb5test"
	"github.com/zephyr-im/zephyr-go/zephyrtest"
)

type noticeWithAuth struct {
	notice     *Notice
	authStatus AuthStatus
}

func mockSendingServer(
	t *testing.T,
	client net.Addr,
	key *krb5.KeyBlock,
	conn net.PacketConn,
	notices []noticeWithAuth,
) {
	// Set some stuff up.
	l, lc := expectNoLogs(t)
	defer lc.Close()
	ctx, keytab := makeServerContextAndKeyTab(t)
	defer ctx.Free()
	defer keytab.Close()

	rawNotices := ReadRawNotices(conn, l)
	for _, n := range notices {
		// Assemble the notice to send out.
		pkt, err := n.notice.EncodePacketForClient(ctx, n.authStatus, key)
		if err != nil {
			t.Fatalf("Error encoding notice: %v", err)
		}

		// Send to the client.
		_, err = conn.WriteTo(pkt, client)
		if err != nil {
			t.Fatalf("Failed to send packet")
		}

		// Expect a CLIENTACK.
		reply, ok := <-rawNotices
		if !ok {
			t.Errorf("Did not receive ACK from client")
		}
		ack, err := DecodeRawNotice(reply.RawNotice)
		if err != nil {
			t.Errorf("Failed to record ACK: %v", err)
		}
		if ack.Kind != CLIENTACK || !ack.UID.Equal(n.notice.UID) {
			t.Errorf("Expected CLIENTACK; got %v", ack)
		}
	}
	conn.Close()
}

func TestSession(t *testing.T) {
	l, lc := expectNoLogs(t)
	defer lc.Close()
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()

	// Set up out network.
	clock := zephyrtest.NewMockClock()
	client, server1, server2 := mockNetwork2()
	session, err := NewSessionFull(client, serverConfigFull, krb5test.Credential(),
		l, clock)
	if err != nil {
		t.Fatal(err)
	}

	uid1 := MakeUID(clientAddr.IP, time.Unix(1, 0))
	uid2 := MakeUID(clientAddr.IP, time.Unix(2, 0))
	uid3 := MakeUID(clientAddr.IP, time.Unix(3, 0))
	uid4 := MakeUID(clientAddr.IP, time.Unix(4, 0))
	uid5 := MakeUID(clientAddr.IP, time.Unix(5, 0))
	uid6 := MakeUID(clientAddr.IP, time.Unix(6, 0))
	uid7 := MakeUID(clientAddr.IP, time.Unix(7, 0))
	uid8 := MakeUID(clientAddr.IP, time.Unix(8, 0))

	// Put together two servers. Each server sends some set of
	// messages. Use two to assert that ACKs go to the server that
	// expects them. This test will test reassembly and
	// deduplicating and ACK behavior.
	notices1 := []noticeWithAuth{
		// Two copies of a notice. Only receive one, but ACK both.
		{sampleNoticeWithUID(uid1), AuthYes},
		{sampleNoticeWithUID(uid1), AuthYes},
		// Dedup works even when auth changes; this is needed
		// for now because of a historical zhm bug on legacy
		// clients.
		{sampleNoticeWithUID(uid1), AuthFailed},
		// A sharded notice.
		{longMessageChunk(uid2, uid2, 0, 128), AuthYes},
		{longMessageChunk(uid3, uid2, 128, 128), AuthYes},
		// Another sharded notice. Half comes from the other server.
		{longMessageChunk(uid4, uid4, 0, 128), AuthYes},
		// Another copy of the first; still only receive one.
		{longMessageChunk(uid2, uid2, 0, 128), AuthYes},
		{longMessageChunk(uid3, uid2, 128, 128), AuthYes},
		// To ensure that everything else ACKed properly, add
		// a redundant test at the end.
		{longMessageChunk(uid7, uid7, 0, 128), AuthYes},
	}
	notices2 := []noticeWithAuth{
		// Sharded notice that never completes.
		{longMessageChunk(uid5, uid5, 0, 128), AuthYes},
		// Other half of the last sharded notice. This comes
		// from the other server, so ACKs should go there.
		{longMessageChunk(uid6, uid4, 128, 128), AuthFailed},
		// Dedup works across servers.
		{sampleNoticeWithUID(uid1), AuthYes},
		// To ensure that everything else ACKed properly, add
		// a redundant test at the end.
		{longMessageChunk(uid8, uid7, 128, 128), AuthYes},
	}

	// Spin up our two servers.
	go mockSendingServer(t, clientAddr, krb5test.SessionKey(), server1, notices1)
	go mockSendingServer(t, clientAddr, krb5test.SessionKey(), server2, notices2)

	messages := []MessageReaderResult{
		{sampleMessage(uid1, sampleNotice().RawBody), AuthYes},
		{sampleMessage(uid2, longMessage), AuthYes},
		{sampleMessage(uid4, longMessage), AuthFailed},
		{sampleMessage(uid7, longMessage), AuthYes},
	}
	for _, expected := range messages {
		m := <-session.Messages()
		if m.AuthStatus != expected.AuthStatus {
			t.Errorf("AuthStatus = %v; want %v",
				m.AuthStatus, expected.AuthStatus)
		}
		expectHeadersEqual(t, &m.Message.Header, &expected.Message.Header)
		if !reflect.DeepEqual(m.Message.Body, expected.Message.Body) {
			t.Errorf("m.Body = %v; want %v",
				m.Message.Body, expected.Message.Body)
		}
	}
	session.Close()
	for m := range session.Messages() {
		t.Errorf("Unexpected message: %v", m)
	}
}
