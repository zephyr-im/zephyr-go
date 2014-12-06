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
	"container/heap"
	"time"
)

// TODO(davidben): The key should include the sender. Probably also
// the AuthStatus.

type uidItem struct {
	uid    UID
	expire time.Time
	index  int
	value  interface{}
}

type uidList []*uidItem

func (ul uidList) Len() int { return len(ul) }

func (ul uidList) Less(i, j int) bool {
	return ul[i].expire.Before(ul[j].expire)
}

func (ul uidList) Swap(i, j int) {
	ul[i], ul[j] = ul[j], ul[i]
	ul[i].index = i
	ul[j].index = j
}

func (ul *uidList) Push(x interface{}) {
	n := len(*ul)
	item := x.(*uidItem)
	item.index = n
	*ul = append(*ul, item)
}

func (ul *uidList) Pop() interface{} {
	old := *ul
	n := len(old)
	item := old[n-1]
	item.index = -1 // for safety
	*ul = old[0 : n-1]
	return item
}

// A WindowedMap is a map from UID to some value type where keys
// expire if not accessed for some time.
type WindowedMap struct {
	clock    Clock
	lifetime time.Duration
	uidMap   map[UID]*uidItem
	uidList  uidList
}

// NewWindowedMap creates a new WindowedMap with the specified
// lifetime for key entries.
func NewWindowedMap(lifetime time.Duration) *WindowedMap {
	return NewWindowedMapFull(lifetime, SystemClock)
}

// NewWindowedMapFull creates a new WindowedMap with the specified
// lifetime for key entries. It allows passing a custom Clock
// implementation for testing purposes.
func NewWindowedMapFull(lifetime time.Duration, clock Clock) *WindowedMap {
	w := &WindowedMap{clock, lifetime, map[UID]*uidItem{}, uidList{}}
	heap.Init(&w.uidList)
	return w
}

// Len returns the number of entries in the windowed map. Note that
// this does not get updated for any entries that map have expired
// since the last lookup or modification.
func (w *WindowedMap) Len() int {
	return len(w.uidList)
}

// ExpireOldEntries removes entries from the windowed map which have
// since expired.
func (w *WindowedMap) ExpireOldEntries() {
	if len(w.uidList) != len(w.uidMap) {
		panic(*w)
	}
	now := w.clock.Now()
	for len(w.uidList) > 0 && !w.uidList[0].expire.After(now) {
		delete(w.uidMap, w.uidList[0].uid)
		heap.Remove(&w.uidList, 0)
	}
}

// Lookup looks up the value for a given UID. The second return value
// is false if the key is not in the map. Looking up a UID updates the
// access time for that key.
func (w *WindowedMap) Lookup(uid UID) (interface{}, bool) {
	w.ExpireOldEntries()
	item, ok := w.uidMap[uid]
	if !ok {
		return nil, false
	}
	w.Put(uid, item.value)
	return item.value, true
}

// Remove removes the entry for a given UID and returns the value
// associated with it. The second return value is false if the key is
// not in the map.
func (w *WindowedMap) Remove(uid UID) (interface{}, bool) {
	w.ExpireOldEntries()
	item, ok := w.uidMap[uid]
	if !ok {
		return nil, false
	}
	heap.Remove(&w.uidList, item.index)
	delete(w.uidMap, uid)
	return item.value, true
}

// Put inserts a new value into the windowed map, overriding the
// existing value for UID if it already exists.
func (w *WindowedMap) Put(uid UID, value interface{}) {
	if _, ok := w.uidMap[uid]; ok {
		w.Remove(uid)
	}
	item := &uidItem{uid, w.clock.Now().Add(w.lifetime), -1, value}
	heap.Push(&w.uidList, item)
	w.uidMap[uid] = item
}
