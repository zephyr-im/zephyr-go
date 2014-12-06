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

type temporaryError struct{}

func (temporaryError) Error() string {
	return "Temporary error"
}

func (temporaryError) Timeout() bool {
	return false
}

func (temporaryError) Temporary() bool {
	return true
}

// TemporaryError is a mock temporary net.Error.
var TemporaryError temporaryError
