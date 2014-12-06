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
	"reflect"
	"strings"
	"testing"

	"github.com/zephyr-im/krb5-go"
	"github.com/zephyr-im/krb5-go/krb5test"
)

func makeServerContextAndKeyTab(t *testing.T) (*krb5.Context, *krb5.KeyTab) {
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	keytab, err := krb5test.MakeServerKeyTab(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, keytab
}

func TestParseZephyrVersion(t *testing.T) {
	if major, minor, err := parseZephyrVersion("ZEPH0.2"); err != nil {
		t.Errorf("parseZephyrVersion(\"ZEPH0.2\") failed: %v", err)
	} else if major != 0 || minor != 2 {
		t.Errorf("parseZephyrVersion(\"ZEPH0.2\") = %v, %v; want %v, %v",
			major, minor, 0, 2)
	}

	if vers := formatZephyrVersion(0, 2); vers != "ZEPH0.2" {
		t.Errorf("formatZephyrVersion(0, 2) = %v; want \"ZEPH0.2\"", vers)
	}

	badVersion := []string{
		"BOGUS4.2",
		"ZEPHYR0.2",
		"ZEPH0.1.2",
		"zeph0.2",
		"ZEPHa.b",
		"ZEPH",
		"ZEPH-1.-2",
	}
	for _, version := range badVersion {
		if major, minor, err := parseZephyrVersion(version); err == nil {
			t.Errorf("parseZephyrVersion(%q) unexpectedly succeeded: %v, %v",
				version, major, minor)
		}
	}
}

// Test some completely bogus packets.
func TestDecodeBadPackets(t *testing.T) {
	type bad struct {
		pkt []byte
		err error
	}
	badPackets := []bad{
		// Bogus.
		bad{[]byte(""), ErrBadPacketFormat},
		// Bad version.
		bad{[]byte("Blah\x00Blah\x00Blah"), ErrBadVersionFormat},
		// Major version mismatch.
		bad{[]byte("ZEPH1.2\x000x00000002\x00hi"), ErrBadPacketVersion},
		// Bad field count zephyrascii.
		bad{[]byte("ZEPH0.2\x00two\x00hi"), nil},
		// Too few fields.
		bad{[]byte("ZEPH0.2\x000x00000002\x00hi"), ErrBadPacketFieldCount},
		// Too few fields.
		bad{makeTestPacket(1, "0x0000000E"), ErrBadPacketFieldCount},
		// Field count too high.
		bad{makeTestPacket(1, "0x00000020"), ErrBadPacketFieldCount},
		// Giant field count.
		bad{makeTestPacket(1, "0xFFFFFFFF"), ErrBadPacketFieldCount},
	}
	for _, test := range badPackets {
		if raw, err := DecodePacket([]byte(test.pkt)); err == nil {
			t.Errorf("DecodePacket(%q) = %v; want error", test.pkt, raw)
		} else if test.err != nil && err != test.err {
			t.Errorf("DecodePacket(%q) failed with %v; want %v",
				test.pkt, err, test.err)
		}
	}
}

func TestDecodePacket(t *testing.T) {
	pkt := samplePacket()
	expectedRaw := sampleRawNotice()
	if raw, err := DecodePacket(pkt); err != nil {
		t.Errorf("DecodePacket(%q) failed: %v", string(pkt), err)
	} else if !reflect.DeepEqual(raw, expectedRaw) {
		t.Errorf("DecodePacket(%q) = %v\nwant %v", string(pkt), raw, expectedRaw)
	}

	// Packets with 15 fields are okay.
	pkt = makeTestPacket(1, "0x0000000F")
	if _, err := DecodePacket(pkt); err != nil {
		t.Errorf("DecodePacket(%q) failed: %v", string(pkt), err)
	}

	// Packets with extra fields are okay.
	pkt = makeTestPacket(1, "0x00000014")
	if _, err := DecodePacket(pkt); err != nil {
		t.Errorf("DecodePacket(%q) failed: %v", string(pkt), err)
	}
}

func TestDecodeAuthenticator(t *testing.T) {
	raw := sampleRawNotice()
	raw.HeaderFields[6] = []byte("0x00000004")
	raw.HeaderFields[7] = []byte("Ztest")

	if auth, err := raw.DecodeAuthenticator(); err != nil {
		t.Errorf("raw.DecodeAuthenticator() failed: %v", err)
	} else if string(auth) != "test" {
		t.Errorf("raw.DecodeAuthenticator() = %q; want %q", auth, "test")
	}

	// Bogus length.
	raw.HeaderFields[6] = []byte("bogus")
	if _, err := raw.DecodeAuthenticator(); err == nil {
		t.Errorf("raw.DecodeAuthenticator() unexpected succeeded")
	}

	// Mismatch length.
	raw.HeaderFields[6] = []byte("0xDEADBEEF")
	if _, err := raw.DecodeAuthenticator(); err == nil {
		t.Errorf("raw.DecodeAuthenticator() unexpected succeeded")
	} else if err != ErrAuthenticatorLengthMismatch {
		t.Errorf("raw.DecodeAuthenticator() gave the wrong error: %v", err)
	}

	// Bad zcode.
	raw.HeaderFields[7] = []byte("notvalidzcode")
	if _, err := raw.DecodeAuthenticator(); err == nil {
		t.Errorf("raw.DecodeAuthenticator() unexpected succeeded")
	}
}

func TestDecodeChecksum(t *testing.T) {
	raw := sampleRawNotice()

	if cksum, err := raw.DecodeChecksum(); err != nil {
		t.Errorf("raw.DecodeChecksum() failed: %v", err)
	} else if !bytes.Equal(cksum, sampleChecksum()) {
		t.Errorf("raw.DecodeChecksum() = %q; want %q", cksum, sampleChecksum())
	}

	// Bad zcode.
	raw.HeaderFields[14] = []byte("notvalidzcode")
	if _, err := raw.DecodeChecksum(); err == nil {
		t.Errorf("raw.DecodeChecksum() unexpected succeeded")
	}
}

func TestDecodeAuthStatus(t *testing.T) {
	raw := sampleRawNotice()

	if auth, err := raw.DecodeAuthStatus(); err != nil {
		t.Errorf("raw.DecodeAuthStatus() failed: %v", err)
	} else if auth != AuthYes {
		t.Errorf("raw.DecodeAuthStatus() = %q; want %q", auth, AuthYes)
	}

	// Bad authstatus.
	raw.HeaderFields[5] = []byte("notvalidzascii")
	if _, err := raw.DecodeAuthStatus(); err == nil {
		t.Errorf("raw.DecodeAuthStatus() unexpected succeeded")
	}
}

func TestEncodePacket(t *testing.T) {
	raw := sampleRawNotice()
	expected := string(samplePacket())
	if enc := string(raw.EncodePacket()); enc != expected {
		t.Errorf("raw.EncodePacket() = %q; want %q", enc, expected)
	}
}

func TestChecksumPayload(t *testing.T) {
	raw := sampleRawNotice()
	expected := strings.Replace(string(samplePacket()),
		string(sampleChecksumZcode())+"\x00", "", 1)
	if enc := string(raw.ChecksumPayload()); enc != expected {
		t.Errorf("raw.ChecksumPayload() = %q; want %q", enc, expected)
	}
}

func TestCheckAuthFromServer(t *testing.T) {
	raw := sampleRawNotice()
	key := sampleKeyBlock()
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Free()

	if auth, err := raw.CheckAuthFromServer(ctx, key); err != nil {
		t.Errorf("raw.CheckAuthFromServer() failed: %v", err)
	} else if auth != AuthYes {
		t.Errorf("raw.CheckAuthFromServer() = %v; want %v", auth, AuthYes)
	}

	// Break some random thing.
	raw.HeaderFields[0] = []byte("moooo")
	if auth, err := raw.CheckAuthFromServer(ctx, key); err != nil {
		t.Errorf("raw.CheckAuthFromServer() failed: %v", err)
	} else if auth != AuthFailed {
		t.Errorf("raw.CheckAuthFromServer() = %v; want %v", auth, AuthFailed)
	}

	// Doesn't claim authentication.
	raw = sampleRawNotice()
	raw.HeaderFields[5] = []byte("0x00000000")
	if auth, err := raw.CheckAuthFromServer(ctx, key); err != nil {
		t.Errorf("raw.CheckAuthFromServer() failed: %v", err)
	} else if auth != AuthNo {
		t.Errorf("raw.CheckAuthFromServer() = %v; want %v", auth, AuthNo)
	}

	// Bogus authstatus.
	raw.HeaderFields[5] = []byte("bogus")
	if _, err := raw.CheckAuthFromServer(ctx, key); err == nil {
		t.Errorf("raw.CheckAuthFromServer() unexpectedly ran")
	}

	// Checksum length error.
	raw = sampleRawNotice()
	raw.HeaderFields[14] = []byte("Zasdf")
	if _, err := raw.CheckAuthFromServer(ctx, key); err == nil {
		t.Errorf("raw.CheckAuthFromServer() unexpectedly ran")
	}

	// Bogus checksum.
	raw.HeaderFields[14] = []byte("bogus")
	if _, err := raw.CheckAuthFromServer(ctx, key); err == nil {
		t.Errorf("raw.CheckAuthFromServer() unexpectedly ran")
	}
}

func TestClientToServerAuth(t *testing.T) {
	// The client makes the notice.
	clientCtx, err := krb5.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer clientCtx.Free()
	notice := sampleNotice()
	raw, err := notice.EncodeRawNoticeForServer(
		clientCtx, krb5test.Credential())
	if err != nil {
		t.Fatalf("notice.EncodeRawNoticeForServer failed: %v", err)
	}

	// Server checks the notice.
	serverCtx, keytab := makeServerContextAndKeyTab(t)
	defer serverCtx.Free()
	defer keytab.Close()
	auth, key, err := raw.CheckAuthFromClient(serverCtx, krb5test.Service(), keytab)
	if err != nil {
		t.Errorf("CheckAuthFromClient failed: %v", err)
	} else {
		if auth != AuthYes {
			t.Errorf("CheckAuthFromClient returned %v; want AuthYes", auth)
		}
		if !reflect.DeepEqual(key, krb5test.SessionKey()) {
			t.Errorf("CheckAuthFromClient return %v; want %v",
				key, krb5test.SessionKey())
		}
	}

	// Perturb the checksum a little. It should fail now.
	cksum, err := raw.DecodeChecksum()
	if err != nil {
		t.Fatal(err)
	}
	cksum[0]++
	raw.HeaderFields[14] = EncodeZcode(cksum)
	auth, _, err = raw.CheckAuthFromClient(serverCtx, krb5test.Service(), keytab)
	if err != nil {
		t.Errorf("CheckAuthFromClient failed: %v", err)
	} else if auth != AuthFailed {
		t.Errorf("CheckAuthFromClient returned %v; want AuthFailed", auth)
	}

	// Malformed checksums also fail.
	raw.HeaderFields[14] = []byte("bogus")
	auth, _, _ = raw.CheckAuthFromClient(serverCtx, krb5test.Service(), keytab)
	if auth != AuthFailed {
		t.Errorf("CheckAuthFromClient returned %v; want AuthFailed", auth)
	}

	// An unauthenticated packet should return unauthenticated.
	raw = notice.EncodeRawNoticeUnauth()
	auth, _, err = raw.CheckAuthFromClient(serverCtx, krb5test.Service(), keytab)
	if err != nil {
		t.Errorf("CheckAuthFromClient failed: %v", err)
	} else if auth != AuthNo {
		t.Errorf("CheckAuthFromClient returned %v; want AuthNo", auth)
	}

	// Malformed authstatus fields error.
	raw.HeaderFields[5] = []byte("bogus")
	auth, _, _ = raw.CheckAuthFromClient(serverCtx, krb5test.Service(), keytab)
	if auth != AuthFailed {
		t.Errorf("CheckAuthFromClient returned %v; want AuthFailed", auth)
	}

	// Bad authenticator fails.
	raw, err = notice.EncodeRawNoticeForServer(
		clientCtx, krb5test.Credential())
	if err != nil {
		t.Fatalf("notice.EncodeRawNoticeForServer failed: %v", err)
	}
	raw.HeaderFields[6] = []byte("0x00000005")
	raw.HeaderFields[7] = []byte("Z12345")
	auth, _, _ = raw.CheckAuthFromClient(serverCtx, krb5test.Service(), keytab)
	if auth != AuthFailed {
		t.Errorf("CheckAuthFromClient returned %v; want AuthFailed", auth)
	}

	// Malformed authenticator fails.
	raw.HeaderFields[7] = []byte("Bogus")
	auth, _, _ = raw.CheckAuthFromClient(serverCtx, krb5test.Service(), keytab)
	if auth != AuthFailed {
		t.Errorf("CheckAuthFromClient returned %v; want AuthFailed", auth)
	}
}
