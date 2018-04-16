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
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/zephyr-im/krb5-go"
)

// A Kind is the first field a zephyr notice.
type Kind uint32

const (
	// UNSAFE notices are acknowledged by neither the server nor
	// the zhm (in implementations which use one).
	UNSAFE Kind = 0
	// UNACKED notices are not acknowledged by the server.
	UNACKED Kind = 1
	// ACKED notices are acknowledged by the server with a
	// SERVACK.
	ACKED Kind = 2
	// HMACK notices are zhm acknowledgements.
	HMACK Kind = 3
	// HMCTL notices are used in communications between the server
	// and the zhm.
	HMCTL Kind = 4
	// SERVACK notices are acknowledgements from the server that a
	// notice was accepted for delivery.
	SERVACK Kind = 5
	// SERVNAK notices are acknowledgements from the server that a
	// notice was received but not delivered for some reason.
	SERVNAK Kind = 6
	// CLIENTACK notices are sent by the client to acknowledgement
	// a notice from the server.
	CLIENTACK Kind = 7
	// STAT notices are used to request statistics from the zhm.
	STAT Kind = 8
)

func (k Kind) String() string {
	switch k {
	case UNSAFE:
		return "UNSAFE"
	case UNACKED:
		return "UNACKED"
	case ACKED:
		return "ACKED"
	case HMACK:
		return "HMACK"
	case HMCTL:
		return "HMCTL"
	case SERVACK:
		return "SERVACK"
	case SERVNAK:
		return "SERVNAK"
	case CLIENTACK:
		return "CLIENTACK"
	case STAT:
		return "STAT"
	default:
		return strconv.FormatUint(uint64(k), 10)
	}
}

// IsACK returns whether this is a server or client
// acknowledgement.
func (k Kind) IsACK() bool {
	return k.IsServerACK() || k == CLIENTACK
}

// IsServerACK returns whether this is a SERVACK or SERVNAK.
func (k Kind) IsServerACK() bool {
	return k == SERVACK || k == SERVNAK
}

// ExpectsServerACK returns whether the client expects a server
// acknowledgement in response to this packet.
func (k Kind) ExpectsServerACK() bool {
	return k == ACKED
}

// ExpectsClientACK returns whether the server expects a client
// acknowledgement in response to this packet.
func (k Kind) ExpectsClientACK() bool {
	return k != HMACK && k != SERVACK && k != SERVNAK && k != CLIENTACK
}

// A Charset is the value of the "charset" field of a zephyr
// notice. Note that this field has a number of historical
// quirks. Only CharsetUTF8 or the byte-swapped version of it are
// really meaningful.
type Charset uint16

// The set of Charset values defined as well as one for byte-swapped
// UTF-8 for compatibility with a zephyr bug.
const (
	CharsetUnknown     Charset = 0x0000
	CharsetISO8859_1   Charset = 0x0004
	CharsetUTF8        Charset = 0x006a
	CharsetUTF8Swapped Charset = 0x6a00
)

func (cs Charset) String() string {
	switch cs {
	case CharsetUnknown:
		return "Unknown charset"
	case CharsetISO8859_1:
		return "ISO 8859-1"
	case CharsetUTF8:
		return "UTF-8"
	case CharsetUTF8Swapped:
		return "UTF-8 (byte-swapped)"
	default:
		return strconv.FormatUint(uint64(cs), 10)
	}
}

func byteSwap16(n uint16) uint16 {
	return ((n & 0xff) << 8) | (n >> 8)
}

// ErrBadField is returned if a field is in the wrong format.
var ErrBadField = errors.New("bad field")

// A UID is the identifier of a zephyr notice. It includes the
// sender's IP address and the send time.
type UID [12]byte

func decodeUID(inp []byte) (*UID, error) {
	if DecodedZAsciiLength(len(inp)) != 12 {
		return nil, ErrBadField
	}
	var out UID
	if l, err := DecodeZAsciiInto(out[:], inp); err != nil {
		return nil, err
	} else if l != 12 {
		panic(l)
	}
	return &out, nil
}

// MakeUID creates a uid out of an IP address and time. If ip is not
// an IPv4 address, the last four bytes are taken.
func MakeUID(ip net.IP, time time.Time) UID {
	var uid UID
	copy(uid[:4], ip[len(ip)-4:])
	binary.BigEndian.PutUint32(uid[4:8], uint32(time.Unix()))
	binary.BigEndian.PutUint32(uid[8:12], uint32(time.Nanosecond()/1000))
	return uid
}

// IP returns the IP address portion of the uid.
func (uid UID) IP() net.IP {
	return net.IP(uid[0:4])
}

// Time returns the time portion of the uid.
func (uid UID) Time() time.Time {
	seconds := int64(binary.BigEndian.Uint32(uid[4:8]))
	useconds := int64(binary.BigEndian.Uint32(uid[8:12]))
	return time.Unix(seconds, useconds*1000)
}

// Equal returns true iff two uids are equal.
func (uid UID) Equal(x UID) bool {
	return bytes.Equal(uid[:], x[:])
}

// A Header is the set of common metadata between a Notice and a
// reassembled Message.
type Header struct {
	Kind          Kind
	UID           UID
	Port          uint16
	Class         string
	Instance      string
	OpCode        string
	Sender        string
	Recipient     string
	DefaultFormat string
	SenderAddress net.IP
	Charset       Charset
	OtherFields   [][]byte
}

// A Notice is a raw message sent and received over zephyr.
type Notice struct {
	Header
	Multipart string
	MultiUID  UID
	RawBody   []byte
}

// DecodeRawNotice decodes a RawNotice into a Notice. The underlying
// byte slices on the result do not share backing stores with the
// RawNotice.
func DecodeRawNotice(r *RawNotice) (*Notice, error) {
	kind, err := DecodeZAscii32(r.HeaderFields[kindIndex])
	if err != nil {
		return nil, err
	}

	uid, err := decodeUID(r.HeaderFields[uidIndex])
	if err != nil {
		return nil, err
	}

	port, err := DecodeZAscii16(r.HeaderFields[portIndex])
	if err != nil {
		return nil, err
	}

	class := string(r.HeaderFields[classIndex])
	instance := string(r.HeaderFields[instanceIndex])
	opcode := string(r.HeaderFields[opcodeIndex])
	sender := string(r.HeaderFields[senderIndex])
	recipient := string(r.HeaderFields[recipientIndex])
	defaultFormat := string(r.HeaderFields[defaultformatIndex])

	multipart := ""
	multiuid := uid
	if len(r.HeaderFields) > multiuidIndex {
		multipart = string(r.HeaderFields[multipartIndex])

		multiuid, err = decodeUID(r.HeaderFields[multiuidIndex])
		if err != nil {
			return nil, err
		}
	}

	var senderAddress net.IP
	if len(r.HeaderFields) > senderSockaddrIndex {
		sockaddrField := r.HeaderFields[senderSockaddrIndex]
		var ipBytes []byte
		if len(sockaddrField) != 0 && sockaddrField[0] == 'Z' {
			ipBytes, err = DecodeZcode(sockaddrField)
		} else {
			ipBytes, err = DecodeZAscii(sockaddrField)
		}
		if err != nil {
			return nil, err
		}
		if len(ipBytes) != net.IPv4len && len(ipBytes) != net.IPv6len {
			return nil, ErrBadField
		}
		senderAddress = net.IP(ipBytes)
	} else {
		senderAddress = uid.IP()
	}

	charset := CharsetUnknown
	otherfields := [][]byte{}
	if len(r.HeaderFields) > charsetIndex {
		charsetRaw, err := DecodeZAscii16(r.HeaderFields[charsetIndex])
		if err != nil {
			return nil, err
		}
		// The charset gets byte-swapped. Why? Good question.
		charset = Charset(byteSwap16(charsetRaw))
		// This really should be a static assert...
		if numKnownFields != charsetIndex+1 {
			panic(numKnownFields)
		}
		otherfields = copyByteSlices(r.HeaderFields[numKnownFields:])
	}

	return &Notice{
		Header: Header{
			Kind:          Kind(kind),
			UID:           *uid,
			Port:          port,
			Class:         class,
			Instance:      instance,
			OpCode:        opcode,
			Sender:        sender,
			Recipient:     recipient,
			DefaultFormat: defaultFormat,
			SenderAddress: senderAddress,
			Charset:       charset,
			OtherFields:   otherfields,
		},
		Multipart: multipart,
		MultiUID:  *multiuid,
		RawBody:   copyByteSlice(r.Body)}, nil
}

func (n *Notice) encodeRawNotice(
	authstatus AuthStatus, authenticator []byte) *RawNotice {
	fields := make([][]byte, numKnownFields, numKnownFields+len(n.OtherFields))

	fields[versionIndex] = []byte(formatZephyrVersion(
		ProtocolVersionMajor, ProtocolVersionMinor))
	fields[numfieldsIndex] = EncodeZAscii32(uint32(len(fields)))
	fields[kindIndex] = EncodeZAscii32(uint32(n.Kind))
	fields[uidIndex] = EncodeZAscii(n.UID[:])
	fields[portIndex] = EncodeZAscii16(n.Port)
	fields[authstatusIndex] = EncodeZAscii32(uint32(authstatus))
	fields[authlenIndex] = EncodeZAscii32(uint32(len(authenticator)))
	if authenticator != nil {
		fields[authenticatorIndex] = EncodeZcode(authenticator)
	} else {
		fields[authenticatorIndex] = []byte{}
	}
	fields[classIndex] = []byte(n.Class)
	fields[instanceIndex] = []byte(n.Instance)
	fields[opcodeIndex] = []byte(n.OpCode)
	fields[senderIndex] = []byte(n.Sender)
	fields[recipientIndex] = []byte(n.Recipient)
	fields[defaultformatIndex] = []byte(n.DefaultFormat)
	// Checksum gets filled in by the caller.
	fields[checksumIndex] = nil
	fields[multipartIndex] = []byte(n.Multipart)
	fields[multiuidIndex] = EncodeZAscii(n.MultiUID[:])
	if ipv4 := n.SenderAddress.To4(); ipv4 != nil {
		fields[senderSockaddrIndex] = EncodeZcode(ipv4)
	} else {
		fields[senderSockaddrIndex] = EncodeZcode(n.SenderAddress)
	}
	fields[charsetIndex] = EncodeZAscii16(byteSwap16(uint16(n.Charset)))

	fields = append(fields, n.OtherFields...)

	return &RawNotice{fields, n.RawBody}
}

func (n *Notice) encodeRawNoticeWithKey(
	ctx *krb5.Context,
	authstatus AuthStatus,
	authent []byte,
	key *krb5.KeyBlock,
	usage int32) (*RawNotice, error) {

	raw := n.encodeRawNotice(authstatus, authent)
	cksum, err := ctx.MakeChecksum(krb5.SUMTYPE_DEFAULT, key, usage,
		raw.ChecksumPayload())
	if err != nil {
		return nil, err
	}
	raw.HeaderFields[checksumIndex] = EncodeZcode(cksum.Contents)
	return raw, nil
}

// EncodeRawNoticeForServer encodes a Notice into an authenticated
// RawNotice to send to the server. Returns the RawNotice. The
// authenticator always negotiates the key in the credential.
//
// TODO(davidben): Go back to returning the krb5.KeyBlock output from the API?
// Unless we negotiate a subkey, it's guaranteed to be the key in the
// credential anyway, and shared subscriptions require this to be true.
func (n *Notice) EncodeRawNoticeForServer(
	ctx *krb5.Context, cred *krb5.Credential) (*RawNotice, error) {
	authcon, err := ctx.NewAuthContext()
	if err != nil {
		return nil, err
	}
	defer authcon.Free()

	authent, err := authcon.MakeRequest(cred, 0, nil)
	if err != nil {
		return nil, err
	}

	raw, err := n.encodeRawNoticeWithKey(
		ctx, AuthYes, authent, cred.KeyBlock, keyUsageClientCksum)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// EncodeRawNoticeForClient encodes and authenticates a Notice to send
// to a client using a pre-negotiated session key. Returns a RawNotice.
func (n *Notice) EncodeRawNoticeForClient(
	ctx *krb5.Context, authstatus AuthStatus, key *krb5.KeyBlock) (*RawNotice, error) {
	return n.encodeRawNoticeWithKey(
		ctx, authstatus, nil, key, keyUsageServerCksum)
}

// EncodeRawNoticeUnauth encodes a Notice into an unauthenticated
// RawNotice.
func (n *Notice) EncodeRawNoticeUnauth() *RawNotice {
	// No authenticator or checksum.
	raw := n.encodeRawNotice(AuthNo, nil)
	raw.HeaderFields[checksumIndex] = []byte{}
	return raw
}

// EncodePacketForServer encodes and authenticates a Notice to be sent
// to a server. Returns a packet.
func (n *Notice) EncodePacketForServer(
	ctx *krb5.Context, cred *krb5.Credential) ([]byte, error) {
	raw, err := n.EncodeRawNoticeForServer(ctx, cred)
	if err != nil {
		return nil, err
	}
	return raw.EncodePacket(), nil
}

// EncodePacketForClient encodes and authenticates a Notice to be sent
// to a client. Returns a packet.
func (n *Notice) EncodePacketForClient(
	ctx *krb5.Context, authstatus AuthStatus, key *krb5.KeyBlock) ([]byte, error) {
	raw, err := n.EncodeRawNoticeForClient(ctx, authstatus, key)
	if err != nil {
		return nil, err
	}
	return raw.EncodePacket(), nil
}

// EncodePacketUnauth encodes a Notice into an unauthenticated packet.
func (n *Notice) EncodePacketUnauth() []byte {
	return n.EncodeRawNoticeUnauth().EncodePacket()
}

// MakeACK creates an acknowledgement notice for this message. Like
// libzephyr, this preserves the non-body header fields in the
// notice. This is not necessary for a CLIENTACK but is necessary for
// a SERVACK; clients like BarnOwl don't bother associating SERVACKs
// with outgoing messages and just trust the values in the SERVACK.
//
// TODO(davidben): Unlike libzephyr, this doesn't preserve the checksum and
// authenticator. This should be fine. In fact, we can even authenticate ACKs
// without breaking anything.
func (n *Notice) MakeACK(kind Kind, body string) *Notice {
	ack := *n
	ack.Kind = kind
	ack.RawBody = []byte(body)
	return &ack
}
