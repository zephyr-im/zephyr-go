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
	"time"

	"github.com/zephyr-im/zephyr-go/zephyrtest"
)

func TestWindowedMap(t *testing.T) {
	clock := zephyrtest.NewMockClock()
	uid1 := MakeUID(clientAddr.IP, time.Unix(1, 0))
	uid2 := MakeUID(clientAddr.IP, time.Unix(2, 0))

	w := NewWindowedMapFull(5*time.Second, clock)

	// Initially empty.
	if w.Len() != 0 {
		t.Errorf("w.Len() = %d; want 0", w.Len())
	}
	if val, ok := w.Lookup(uid1); ok {
		t.Errorf("w.Lookup(uid1) returned %v, true; want false", val)
	}
	if val, ok := w.Remove(uid1); ok {
		t.Errorf("w.Remove(uid1) returned %v, true; want false", val)
	}

	// Insert something and remove it.
	w.Put(uid1, 1)
	if val, ok := w.Lookup(uid1); !ok || val.(int) != 1 {
		t.Errorf("w.Lookup(uid1) returned %v, %v; want 1", val, ok)
	}
	if w.Len() != 1 {
		t.Errorf("w.Len() = %d; want 1", w.Len())
	}
	if val, ok := w.Remove(uid1); !ok || val.(int) != 1 {
		t.Errorf("w.Remove(uid1) returned %v, %v; want 1", val, ok)
	}

	// Insert something and let it expire.
	w.Put(uid1, 1)
	clock.Advance(5 * time.Second)
	if val, ok := w.Lookup(uid1); ok {
		t.Errorf("w.Lookup(uid1) returned %v, true; want false", val)
	}
	if w.Len() != 0 {
		t.Errorf("w.Len() = %d; want 0", w.Len())
	}

	// Looking up a value updates the expiration time.
	w.Put(uid1, 1)
	w.Put(uid2, 2)
	clock.Advance(2 * time.Second)
	w.Lookup(uid1)
	clock.Advance(3 * time.Second)
	if val, ok := w.Lookup(uid2); ok {
		t.Errorf("w.Lookup(uid2) returned %v, true; want false", val)
	}
	if val, ok := w.Lookup(uid1); !ok || val.(int) != 1 {
		t.Errorf("w.Lookup(uid1) returned %v, %v; want 1", val, ok)
	}
	if w.Len() != 1 {
		t.Errorf("w.Len() = %d; want 1", w.Len())
	}
	clock.Advance(5 * time.Second)
	if val, ok := w.Lookup(uid1); ok {
		t.Errorf("w.Lookup(uid1) returned %v, true; want false", val)
	}
	if w.Len() != 0 {
		t.Errorf("w.Len() = %d; want 0", w.Len())
	}

	// Overriding values works.
	w.Put(uid1, 1)
	w.Put(uid1, 2)
	if val, ok := w.Lookup(uid1); !ok || val.(int) != 2 {
		t.Errorf("w.Lookup(uid1) returned %v, %v; want 2", val, ok)
	}
	if w.Len() != 1 {
		t.Errorf("w.Len() = %d; want 1", w.Len())
	}
}
