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

	"github.com/zephyr-im/krb5-go"
)

const (
	keyUsageClientCksum = 1027
	keyUsageServerCksum = 1029
)

// ErrUnknownEncType is returned when attempting to use a key with an
// unknown enctype.
var ErrUnknownEncType = errors.New("unknown enctype")

// Why is this not exported from MIT Kerberos?
func defaultSumTypeForEncType(enctype krb5.EncType) (krb5.SumType, error) {
	switch enctype {
	case krb5.ENCTYPE_DES_CBC_CRC:
		return krb5.SUMTYPE_RSA_MD5_DES, nil
	case krb5.ENCTYPE_DES_CBC_MD4:
		return krb5.SUMTYPE_RSA_MD4_DES, nil
	case krb5.ENCTYPE_DES_CBC_MD5:
		return krb5.SUMTYPE_RSA_MD5_DES, nil
	case krb5.ENCTYPE_DES3_CBC_SHA1:
		return krb5.SUMTYPE_HMAC_SHA1_DES3, nil
	case krb5.ENCTYPE_AES128_CTS_HMAC_SHA1_96:
		return krb5.SUMTYPE_HMAC_SHA1_96_AES128, nil
	case krb5.ENCTYPE_AES256_CTS_HMAC_SHA1_96:
		return krb5.SUMTYPE_HMAC_SHA1_96_AES256, nil
	case krb5.ENCTYPE_ARCFOUR_HMAC:
		return krb5.SUMTYPE_HMAC_MD5_ARCFOUR, nil
	case krb5.ENCTYPE_ARCFOUR_HMAC_EXP:
		return krb5.SUMTYPE_HMAC_MD5_ARCFOUR, nil
	default:
		return krb5.SUMTYPE_DEFAULT, ErrUnknownEncType
	}
}
