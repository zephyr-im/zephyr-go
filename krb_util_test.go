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
	"testing"

	"github.com/zephyr-im/krb5-go"
)

func TestDefaultSumTypeForEncType(t *testing.T) {
	ctx, err := krb5.NewContext()
	if err != nil {
		t.Fatalf("Could not create context: %v", err)
	}
	defer ctx.Free()

	enctypes := []krb5.EncType{
		krb5.ENCTYPE_DES_CBC_CRC,
		krb5.ENCTYPE_DES_CBC_MD4,
		krb5.ENCTYPE_DES_CBC_MD5,
		krb5.ENCTYPE_DES3_CBC_SHA1,
		krb5.ENCTYPE_AES128_CTS_HMAC_SHA1_96,
		krb5.ENCTYPE_AES256_CTS_HMAC_SHA1_96,
		krb5.ENCTYPE_ARCFOUR_HMAC,
		krb5.ENCTYPE_ARCFOUR_HMAC_EXP,
	}
	usage := int32(0)
	data := []byte("Hello")
	for _, enctype := range enctypes {
		key, err := ctx.MakeRandomKey(enctype)
		if err != nil {
			t.Errorf("ctx.MakeRandomKey(%v) failed: %v", enctype, err)
			continue
		}

		cksum, err := ctx.MakeChecksum(krb5.SUMTYPE_DEFAULT, key, usage, data)
		if err != nil {
			t.Errorf("ctx.MakeCheckum(%v, %v) failed: %v", key, data, err)
			continue
		}

		if sumtype, err := defaultSumTypeForEncType(enctype); err != nil {
			t.Errorf("defaultSumTypeForEncType(%v) failed: %v", enctype, err)
		} else if sumtype != cksum.SumType {
			t.Errorf("defaultSumTypeForEncType(%v) = %v; want %v",
				enctype, sumtype, cksum.SumType)
		}
	}

	// Error-handling for some random unknown checksum.
	if _, err := defaultSumTypeForEncType(krb5.ENCTYPE_DES_CBC_RAW); err == nil {
		t.Errorf("defaultSumTypeForEncType(krb5.ENCTYPE_DES_CBC_RAW) did not fail")
	}
}
