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
	"strconv"
	"strings"

	"github.com/zephyr-im/krb5-go"
)

// AuthStatus is the result of authenticating a notice.
type AuthStatus uint32

const (
	// AuthFailed describes a notice which failed authentication
	// for some reason.
	AuthFailed AuthStatus = 0xffffffff
	// AuthYes describes an authenticated notice.
	AuthYes AuthStatus = 1
	// AuthNo describes a notice which did not claim to be
	// authenticated.
	AuthNo AuthStatus = 0
)

func (as AuthStatus) String() string {
	switch as {
	case AuthFailed:
		return "AuthFailed"
	case AuthYes:
		return "AuthYes"
	case AuthNo:
		return "AuthNo"
	default:
		return strconv.FormatUint(uint64(as), 10)
	}
}

// ErrBadVersionFormat is returned when a zephyr version field cannot
// be parsed.
var ErrBadVersionFormat = errors.New("bad version format")

const zephyrVersionHeader = "ZEPH"

// ProtocolVersionMajor and ProtocolVersionMinor are the version of
// the zephyr protocol implemented by this library.
const (
	ProtocolVersionMajor = 0
	ProtocolVersionMinor = 2
)

func parseZephyrVersion(version string) (uint, uint, error) {
	if !strings.HasPrefix(version, zephyrVersionHeader) {
		return 0, 0, ErrBadVersionFormat
	}
	split := strings.SplitN(version[len(zephyrVersionHeader):], ".", 2)
	if len(split) != 2 {
		return 0, 0, ErrBadVersionFormat
	}
	major, err := strconv.ParseUint(split[0], 10, 0)
	if err != nil {
		return 0, 0, err
	}
	minor, err := strconv.ParseUint(split[1], 10, 0)
	if err != nil {
		return 0, 0, err
	}
	return uint(major), uint(minor), nil
}

func formatZephyrVersion(major, minor uint) string {
	return zephyrVersionHeader +
		strconv.FormatUint(uint64(major), 10) +
		"." +
		strconv.FormatUint(uint64(minor), 10)
}

// Processing a notice is done in three stages:
//
// - First, we split it up into raw fields and do only basic validation. Just
//   enough to extract the checksum, authenticator, and validate things. This stage
//   gives the RawNotice type.
//
// - Second, we decode the various fields and give back a logical notice. That
//   gives a Notice.
//
// - Third, we process MultiUID and reassemble sharded notices. Tentatively, this
//   will reuse the Notice struct as the only real difference is MultiUID, but
//   we'll see.
//
// Serializing a notice goes in reverse.
//
// TODO(davidben): When serializing, who does UID allocation, the
// library or the user? If the library, it's awkward that the type is
// in there. Perhaps we want a couple more types. The reassembly logic
// could return a tuple of uid, message or so.

// Field layout
const (
	versionIndex       = iota // string
	numfieldsIndex            // zascii32
	kindIndex                 // zascii32
	uidIndex                  // 12-byte zascii
	portIndex                 // zascii16
	authstatusIndex           // zascii32
	authlenIndex              // zascii32
	authenticatorIndex        // zcode
	classIndex                // string
	instanceIndex             // string
	opcodeIndex               // string
	senderIndex               // string
	recipientIndex            // string
	defaultformatIndex        // string
	checksumIndex             // zcode
	// Added in 1988; ZEPHYR0.2
	multipartIndex // string
	multiuidIndex  // 12-byte zascii
	// Added in 2009; no version bump
	senderSockaddrIndex // zcode
	charsetIndex        // zascii16 little-endian
	// Other fields
	numKnownFields
)

const numRequiredFields = checksumIndex + 1

// libzephyr does this awkward thing where it, for purposes of
// authentication checking, it assumes that everything is pointers
// into the z_packet field and does C-style pointer dancing. I'd kinda
// like the intermediate formats to not make assumptions like that, so
// instead we'll use Split/Join being reversible. Zephyr isn't
// terribly well-layered.
//
// Note that this does have one subtlety: we do NOT allow a missing
// body. libzephyr never produces this, but when parsing, it doesn't
// distinguish between
//
//   ZEPH0.2 NUL 0x0000003 NUL blahotherfield
//   ZEPH0.2 NUL 0x0000003 NUL blahotherfield NUL
//
// (Ignore that this notice doesn't pass our minimum field count
// rules.)  In the former, we have three header fields and a missing
// body. In the latter, we have no body. This is relevant because we
// need to be able to reconstruct the concatenation of 0-13 and 15-end
// for checksumming. If this becomes an issue, do something inane like
// treat a nil Body as different.
//
// Delimiter-based serializations. They're the worst.

// A RawNotice is the first stage of processing a packet. The
// individual header fields are parsed out to extract a checksum and
// authenticator. The other fields are uninterpreted.
type RawNotice struct {
	HeaderFields [][]byte
	Body         []byte
}

// ErrBadPacketFormat is returned when parsing a malformed packet.
var ErrBadPacketFormat = errors.New("bad packet format")

// ErrBadPacketFieldCount is returned when parsing a packet with a
// field count that does not match the content.
var ErrBadPacketFieldCount = errors.New("bad field count")

// ErrBadPacketVersion is returned when parsing a packet with an
// incompatible version field.
var ErrBadPacketVersion = errors.New("incompatible packet version")

// DecodePacket records a packet into a RawNotice.
func DecodePacket(packet []byte) (*RawNotice, error) {
	// First, split out the version and field count.
	fs := bytes.SplitN(packet, []byte{0}, 3)

	// We better have at least those fields...
	if len(fs) < 3 {
		return nil, ErrBadPacketFormat
	}
	vers, numFieldsRaw, rest := fs[0], fs[1], fs[2]

	// Like libzephyr, the minor version is ignored in parsing.
	if major, _, err := parseZephyrVersion(string(vers)); err != nil {
		return nil, err
	} else if major != ProtocolVersionMajor {
		return nil, ErrBadPacketVersion
	}

	// Decode the field count.
	numFields, err := DecodeZAscii32(numFieldsRaw)
	if err != nil {
		return nil, err
	}
	// Pfft.
	numFieldsInt := int(numFields)

	// Sanity check; just so we can't be made to allocate giant things or
	// something? Meh. Also require at least 15 fields (ZEPH0.1) so there's
	// a checksum.
	if numFieldsInt > len(packet) || numFieldsInt < numRequiredFields {
		return nil, ErrBadPacketFieldCount
	}

	fields := make([][]byte, 0, numFields)
	fields = append(fields, vers)
	fields = append(fields, numFieldsRaw)

	// Parse the remaining fields. Subtract 2 for version and numfields. Add
	// 1 for the remainder (the body).
	rs := bytes.SplitN(rest, []byte{0}, numFieldsInt-2+1)
	if len(rs) != numFieldsInt-2+1 {
		return nil, ErrBadPacketFieldCount
	}

	// And assemble the RawNotice.
	fields = append(fields, rs[0:len(rs)-1]...)
	if len(fields) != numFieldsInt {
		panic(len(fields))
	}
	body := rs[len(rs)-1]
	return &RawNotice{fields, body}, nil
}

// ErrAuthenticatorLengthMismatch is returned when processing the
// authenticator on a RawNotice where the authlen field does not match
// the length of the decoded authenticator.
var ErrAuthenticatorLengthMismatch = errors.New("authenticator length mismatch")

// DecodeAuthenticator decodes the authenticator field of a RawNotice.
func (r *RawNotice) DecodeAuthenticator() ([]byte, error) {
	// There's this length field. It's completely bogus, but may
	// as well assert that it's right? Be lenient if this causes
	// trouble.
	authlen, err := DecodeZAscii32(r.HeaderFields[authlenIndex])
	if err != nil {
		return nil, err
	}

	// This used to be zephyrascii, but krb4 zephyr stopped
	// working ages ago.
	auth, err := DecodeZcode(r.HeaderFields[authenticatorIndex])
	if err != nil {
		return nil, err
	}
	if len(auth) != int(authlen) {
		return nil, ErrAuthenticatorLengthMismatch
	}
	return auth, nil
}

// DecodeChecksum decodes the checksum field of a RawNotice.
func (r *RawNotice) DecodeChecksum() ([]byte, error) {
	return DecodeZcode(r.HeaderFields[checksumIndex])
}

// DecodeAuthStatus decodes the authstate field of a RawNotice.
func (r *RawNotice) DecodeAuthStatus() (AuthStatus, error) {
	authStatus, err := DecodeZAscii32(r.HeaderFields[authstatusIndex])
	if err != nil {
		return AuthFailed, err
	}
	return AuthStatus(authStatus), nil
}

// ChecksumPayload returns the portion of the packet that is
// checksumed. (The checksum itself is removed and the remainder is
// concatenated.)
func (r *RawNotice) ChecksumPayload() []byte {
	// The part of the packet that's checksummed is really quite
	// absurd, but here we go.
	parts := make([][]byte, 0, len(r.HeaderFields))
	// Fields before the checkum.
	parts = append(parts, r.HeaderFields[0:checksumIndex]...)
	// Fields after the checksum.
	parts = append(parts, r.HeaderFields[checksumIndex+1:]...)
	// Body.
	parts = append(parts, r.Body)
	return bytes.Join(parts, []byte{0})
}

func (r *RawNotice) checkAuth(
	ctx *krb5.Context,
	key *krb5.KeyBlock,
	usage int32,
) (AuthStatus, error) {
	sumtype, err := defaultSumTypeForEncType(key.EncType)
	if err != nil {
		return AuthFailed, err
	}

	checksumData, err := r.DecodeChecksum()
	if err != nil {
		return AuthFailed, err
	}

	checksum := &krb5.Checksum{sumtype, checksumData}

	result, err := ctx.VerifyChecksum(key, usage, r.ChecksumPayload(), checksum)
	if err != nil {
		return AuthFailed, err
	} else if !result {
		return AuthFailed, nil
	} else {
		return AuthYes, nil
	}
}

// CheckAuthFromServer is called by a client to check a packet from
// the server using a previously negotiated key.
func (r *RawNotice) CheckAuthFromServer(
	ctx *krb5.Context,
	key *krb5.KeyBlock,
) (AuthStatus, error) {
	if authStatus, err := r.DecodeAuthStatus(); err != nil {
		return AuthFailed, err
	} else if authStatus != AuthYes {
		return authStatus, nil
	}

	return r.checkAuth(ctx, key, keyUsageServerCksum)
}

// CheckAuthFromClient is called by a server to check a packet from a
// client using a server KeyTab. If successful, the session key from
// the client's authenticator is returned.
func (r *RawNotice) CheckAuthFromClient(
	ctx *krb5.Context,
	service *krb5.Principal,
	keytab *krb5.KeyTab,
) (AuthStatus, *krb5.KeyBlock, error) {
	if authStatus, err := r.DecodeAuthStatus(); err != nil {
		return AuthFailed, nil, err
	} else if authStatus != AuthYes {
		return authStatus, nil, nil
	}

	authcon, err := ctx.NewAuthContext()
	if err != nil {
		return AuthFailed, nil, err
	}
	defer authcon.Free()
	authcon.SetUseTimestamps(false)

	authent, err := r.DecodeAuthenticator()
	if err != nil {
		return AuthFailed, nil, err
	}

	if err := authcon.ReadRequest(authent, service, keytab); err != nil {
		return AuthFailed, nil, err
	}
	key, err := authcon.SessionKey()
	if err != nil {
		return AuthFailed, nil, err
	}

	auth, err := r.checkAuth(ctx, key, keyUsageClientCksum)
	if err != nil {
		return AuthFailed, nil, err
	}
	return auth, key, nil
}

// EncodePacket encodes a RawNotice as a packet. If it is to be
// authenticated, the checksum and (if a client) authenticator fields
// must be already populated.
func (r *RawNotice) EncodePacket() []byte {
	// This function does not check that r.HeaderFields[1] is correct or
	// anything. The caller is expected to provide a legal RawNotice.
	parts := make([][]byte, 0, len(r.HeaderFields)+1)
	parts = append(parts, r.HeaderFields...)
	parts = append(parts, r.Body)
	return bytes.Join(parts, []byte{0})
}
