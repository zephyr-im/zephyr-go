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

package zephyrtest

import (
	"container/heap"
	"sync"
	"time"
)

type timer struct {
	when   time.Time
	signal chan<- time.Time
}

// Implements heap.Interface
type timerList []*timer

func (tl timerList) Len() int {
	return len(tl)
}

func (tl timerList) Less(i, j int) bool {
	return tl[i].when.Before(tl[j].when)
}

func (tl timerList) Swap(i, j int) {
	tl[i], tl[j] = tl[j], tl[i]
}

func (tl *timerList) Push(x interface{}) {
	*tl = append(*tl, x.(*timer))
}

func (tl *timerList) Pop() interface{} {
	old := *tl
	n := len(old)
	timer := old[n-1]
	*tl = old[0 : n-1]
	return timer
}

// A MockClock is a mocked Clock implementation for use with zephyr.
type MockClock struct {
	lock      sync.Mutex
	now       time.Time
	timerList timerList
}

// NewMockClockAt creates a new MockClock at a specific current time.
func NewMockClockAt(now time.Time) *MockClock {
	mc := &MockClock{now: now}
	heap.Init(&mc.timerList)
	return mc
}

// NewMockClock creates a new MockClock.
func NewMockClock() *MockClock {
	return NewMockClockAt(time.Date(1990, 8, 3, 12, 0, 0, 0, time.UTC))
}

// Now is a mocked implementation of time.Now.
func (mc *MockClock) Now() time.Time {
	mc.lock.Lock()
	defer mc.lock.Unlock()
	return mc.now
}

// After is a mocked implementation of time.After.
func (mc *MockClock) After(d time.Duration) <-chan time.Time {
	signal := make(chan time.Time, 1)

	mc.lock.Lock()
	heap.Push(&mc.timerList, &timer{mc.now.Add(d), signal})
	mc.lock.Unlock()

	mc.Advance(0)
	return signal
}

// Advance advances the MockClock by some duration, resolving any
// channels returned by After.
func (mc *MockClock) Advance(d time.Duration) {
	mc.lock.Lock()
	defer mc.lock.Unlock()
	// This is a little wonky. Really it'd be nice to be able to
	// loop and advance + RunUntilIdle or something. Maybe put in
	// a real sleep.
	mc.now = mc.now.Add(d)
	for len(mc.timerList) > 0 && !mc.timerList[0].when.After(mc.now) {
		mc.timerList[0].signal <- mc.timerList[0].when
		heap.Pop(&mc.timerList)
	}
}
