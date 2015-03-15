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
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/zephyr-im/krb5-go"
	"github.com/zephyr-im/krb5-go/krb5test"
	"github.com/zephyr-im/zephyr-go/zephyrtest"
)

var clientAddr = &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 1111}
var serverAddr1 = &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 2222}
var serverAddr2 = &net.UDPAddr{IP: net.IPv4(3, 3, 3, 3), Port: 3333}
var serverConfig = NewStaticServer([]*net.UDPAddr{serverAddr1})
var serverConfigFull = NewStaticServer([]*net.UDPAddr{serverAddr1, serverAddr2})

func mockNetwork1() (net.PacketConn, net.PacketConn) {
	n := zephyrtest.NewMockPacketNetwork(
		[]net.Addr{clientAddr, serverAddr1})
	return n[0], n[1]
}

func mockNetwork2() (net.PacketConn, net.PacketConn, net.PacketConn) {
	n := zephyrtest.NewMockPacketNetwork(
		[]net.Addr{clientAddr, serverAddr1, serverAddr2})
	return n[0], n[1], n[2]
}

func mockServer(t *testing.T,
	conn net.PacketConn,
	expectedNotice *Notice,
	expectedAuthStatus AuthStatus,
	clock *zephyrtest.MockClock,
	numDrop int) {
	// Set some stuff up.
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

		if notice != nil {
			if authStatus != expectedAuthStatus {
				t.Errorf("Bad authStatus %v; want %v",
					authStatus, expectedAuthStatus)
			}
			expectNoticesEqual(t, notice, expectedNotice)
		}

		// Drop the first few packets.
		if numDrop > 0 {
			clock.Advance(time.Minute)
			numDrop--
			continue
		}
		if numDrop == -1 {
			clock.Advance(time.Minute)
			continue
		}

		// Finally, ACK it.
		conn.WriteTo(notice.MakeACK(SERVACK, "SENT").EncodePacketUnauth(), r.Addr)
	}
}

// Tests that a Connection forwards received packets out and doesn't
// send SERVACKs out.
func TestConnectionReceive(t *testing.T) {
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()
	notice := sampleNotice()
	pkt, err := notice.EncodePacketForClient(
		ctx, AuthYes, krb5test.SessionKey())
	if err != nil {
		t.Fatal(err)
	}
	ack := notice.MakeACK(SERVACK, "SENT")

	readChan := make(chan zephyrtest.PacketRead, 2)
	readChan <- zephyrtest.PacketRead{Packet: pkt}
	readChan <- zephyrtest.PacketRead{Packet: ack.EncodePacketUnauth()}
	close(readChan)
	mock := zephyrtest.NewMockPacketConn(clientAddr, readChan)
	clock := zephyrtest.NewMockClock()
	conn, err := NewConnectionFull(mock, serverConfig, krb5test.Credential(), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Check that the credential is the same.
	if !reflect.DeepEqual(conn.Credential(), krb5test.Credential()) {
		t.Errorf("conn.Credential() = %v; want %v", conn.Credential(),
			krb5test.Credential())
	}

	// Read notices out of the connection.
	result := <-conn.Notices()
	expected := NoticeReaderResult{notice, AuthYes, nil}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("<-conn.Notices() = %v; want %v", result, expected)
	}

	result, ok := <-conn.Notices()
	if ok {
		t.Errorf("conn.Notices() did not end: %v", result)
	}
}

func TestConnectionSendNotice(t *testing.T) {
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()
	notice := sampleNotice()

	clock := zephyrtest.NewMockClock()
	client, server := mockNetwork1()
	defer server.Close()
	conn, err := NewConnectionFull(client, serverConfig, krb5test.Credential(),
		clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Set up a "server" to SERVACK notices as they come in.
	go mockServer(t, server, notice, AuthYes, clock, 0)

	ack, err := conn.SendNotice(ctx, notice)
	if err != nil {
		t.Fatalf("SendNotice failed: %v", err)
	}
	if ack.Kind != SERVACK {
		t.Errorf("ack.Kind = %v; want %v", ack.Kind, SERVACK)
	}
	if string(ack.RawBody) != "SENT" {
		t.Errorf("ack.RawBody = %v; want %v", string(ack.RawBody), "SENT")
	}
}

func TestConnectionSendNoticeRetransmit(t *testing.T) {
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()
	notice := sampleNotice()

	clock := zephyrtest.NewMockClock()
	client, server := mockNetwork1()
	defer server.Close()
	conn, err := NewConnectionFull(client, serverConfig, krb5test.Credential(),
		clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Set up a "server" to SERVACK notices as they come in.
	go mockServer(t, server, notice, AuthYes, clock, 2)

	ack, err := conn.SendNotice(ctx, notice)
	if err != nil {
		t.Fatalf("SendNotice failed: %v", err)
	}
	if ack.Kind != SERVACK {
		t.Errorf("ack.Kind = %v; want %v", ack.Kind, SERVACK)
	}
	if string(ack.RawBody) != "SENT" {
		t.Errorf("ack.RawBody = %v; want %v", string(ack.RawBody), "SENT")
	}
}

func TestConnectionSendNoticeTimeout(t *testing.T) {
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()
	notice := sampleNotice()

	clock := zephyrtest.NewMockClock()
	client, server := mockNetwork1()
	defer server.Close()
	conn, err := NewConnectionFull(client, serverConfig, krb5test.Credential(),
		clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Server never responds to anything.
	go mockServer(t, server, notice, AuthYes, clock, -1)

	_, err = conn.SendNotice(ctx, notice)
	if err != ErrSendTimeout {
		t.Fatalf("SendNoticeUnauth did not fail as expected: %v", err)
	}
}

func TestConnectionSendNoticeUnauth(t *testing.T) {
	notice := sampleNotice()
	clock := zephyrtest.NewMockClock()
	client, server := mockNetwork1()
	defer server.Close()
	conn, err := NewConnectionFull(client, serverConfig, krb5test.Credential(),
		clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Set up a "server" to SERVACK notices as they come in.
	go mockServer(t, server, notice, AuthNo, clock, 0)

	ack, err := conn.SendNoticeUnauth(notice)
	if err != nil {
		t.Fatalf("SendNoticeUnauth failed: %v", err)
	}
	if ack.Kind != SERVACK {
		t.Errorf("ack.Kind = %v; want %v", ack.Kind, SERVACK)
	}
	if string(ack.RawBody) != "SENT" {
		t.Errorf("ack.RawBody = %v; want %v", string(ack.RawBody), "SENT")
	}
}

func TestConnectionSendNoticeUnacked(t *testing.T) {
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()
	notice := sampleNotice()
	notice.Kind = UNACKED

	clock := zephyrtest.NewMockClock()
	client, server := mockNetwork1()
	defer server.Close()
	conn, err := NewConnectionFull(client, serverConfig, krb5test.Credential(),
		clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Set up a "server" to never ACK anything.
	go mockServer(t, server, notice, AuthYes, clock, -1)

	ack, err := conn.SendNotice(ctx, notice)
	if err != nil {
		t.Fatalf("SendNotice failed: %v", err)
	}
	if ack != nil {
		t.Errorf("ack = %v; want nil", ack)
	}
}

func TestConnectionSendNoticeRoundRobin(t *testing.T) {
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()
	notice := sampleNotice()

	clock := zephyrtest.NewMockClock()
	client, server1, server2 := mockNetwork2()
	defer server1.Close()
	defer server2.Close()
	conn, err := NewConnectionFull(client, serverConfigFull, krb5test.Credential(),
		clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// server1 never responds to anything. server2 does after the first.
	go mockServer(t, server1, notice, AuthYes, clock, -1)
	go mockServer(t, server2, notice, AuthYes, clock, 1)

	ack, err := conn.SendNotice(ctx, notice)
	if err != nil {
		t.Fatalf("SendNotice failed: %v", err)
	}
	if ack.Kind != SERVACK {
		t.Errorf("ack.Kind = %v; want %v", ack.Kind, SERVACK)
	}
	if string(ack.RawBody) != "SENT" {
		t.Errorf("ack.RawBody = %v; want %v", string(ack.RawBody), "SENT")
	}

	// We should prefer server2 now.
	if sched, idx := conn.schedule(); sched[idx].String() != serverAddr2.String() {
		t.Errorf("Client prefers %v; want %v",
			sched[idx].String(), serverAddr2.String())
	}
}

type needRefresh bool

func (nr *needRefresh) ResolveServer() ([]*net.UDPAddr, error) {
	if !*nr {
		*nr = true
		return []*net.UDPAddr{serverAddr1}, nil
	}
	return []*net.UDPAddr{serverAddr2}, nil
}
func serverConfigNeedRefresh() ServerConfig {
	nr := needRefresh(false)
	return &nr
}

func TestConnectionSendNoticeNeedRefresh(t *testing.T) {
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()
	notice := sampleNotice()

	clock := zephyrtest.NewMockClock()
	client, server1, server2 := mockNetwork2()
	defer server1.Close()
	defer server2.Close()
	conn, err := NewConnectionFull(client, serverConfigNeedRefresh(),
		krb5test.Credential(), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// server1 never responds to anything. server2 is good.
	go mockServer(t, server1, notice, AuthYes, clock, -1)
	go mockServer(t, server2, notice, AuthYes, clock, 0)

	ack, err := conn.SendNotice(ctx, notice)
	if err != nil {
		t.Fatalf("SendNotice failed: %v", err)
	}
	if ack.Kind != SERVACK {
		t.Errorf("ack.Kind = %v; want %v", ack.Kind, SERVACK)
	}
	if string(ack.RawBody) != "SENT" {
		t.Errorf("ack.RawBody = %v; want %v", string(ack.RawBody), "SENT")
	}

	// We should prefer server2 now.
	if sched, idx := conn.schedule(); sched[idx].String() != serverAddr2.String() {
		t.Errorf("Client prefers %v; want %v",
			sched[idx].String(), serverAddr2.String())
	}
}

func TestConnectionSendNoticeWriteFailure(t *testing.T) {
	notice := sampleNotice()
	clock := zephyrtest.NewMockClock()
	readChan := make(chan zephyrtest.PacketRead)
	close(readChan)
	mock := zephyrtest.NewMockPacketConn(clientAddr, readChan)
	conn, err := NewConnectionFull(mock, serverConfig, krb5test.Credential(),
		clock)
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

	_, err = conn.SendNoticeUnauth(notice)
	if err != expectedErr {
		t.Fatalf("SendNoticeUnauth did not fail as expected: %v", err)
	}
}

func TestConnectionSendGiantNotices(t *testing.T) {
	notice := sampleNotice()
	notice.RawBody = make([]byte, 99999)

	clock := zephyrtest.NewMockClock()
	client, server := mockNetwork1()
	defer server.Close()
	conn, err := NewConnectionFull(client, serverConfig, krb5test.Credential(),
		clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = conn.SendNoticeUnauth(notice)
	if err != ErrPacketTooLong {
		t.Fatalf("SendNoticeUnauth did not fail as expected: %v", err)
	}
}

type signalingConfig chan int

func (sc signalingConfig) ResolveServer() ([]*net.UDPAddr, error) {
	sc <- 0
	return []*net.UDPAddr{serverAddr1}, nil
}

func TestConnectionPeriodicRefresh(t *testing.T) {
	config := signalingConfig(make(chan int, 2))

	clock := zephyrtest.NewMockClock()
	client, server := mockNetwork1()
	defer server.Close()
	conn, err := NewConnectionFull(client, config, krb5test.Credential(), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Initial query.
	<-config

	// Periodic refresh.
	clock.Advance(serverRefreshInterval)
	<-config
}

var errFailingConfig = errors.New("hesiod fell over")

type failingConfig struct {
	lock     sync.Mutex
	goodRuns int
	config   ServerConfig
}

func newFailingConfig(goodRuns int, config ServerConfig) ServerConfig {
	return &failingConfig{goodRuns: goodRuns, config: config}
}

func (f *failingConfig) ResolveServer() ([]*net.UDPAddr, error) {
	f.lock.Lock()
	if f.goodRuns == 0 {
		f.lock.Unlock()
		return nil, errFailingConfig
	}
	f.goodRuns--
	f.lock.Unlock()
	return f.config.ResolveServer()
}

func TestConnectionFailingConfigMidSend(t *testing.T) {
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()
	notice := sampleNotice()

	clock := zephyrtest.NewMockClock()
	client, server1, server2 := mockNetwork2()
	defer server1.Close()
	defer server2.Close()
	conn, err := NewConnectionFull(client,
		newFailingConfig(1, serverConfigNeedRefresh()),
		krb5test.Credential(), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// server1 never responds to anything. server2 is good.
	go mockServer(t, server1, notice, AuthYes, clock, -1)
	go mockServer(t, server2, notice, AuthYes, clock, 0)

	ack, err := conn.SendNotice(ctx, notice)
	if err != errFailingConfig {
		t.Fatalf("SendNotice didn't fail as expected: %v %v", ack, err)
	}
}
