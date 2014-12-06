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
	"log"
)

// This is silly. Why doesn't the log package expose the standard
// logger?

func logPrint(l *log.Logger, v ...interface{}) {
	if l != nil {
		l.Print(v...)
	} else {
		log.Print(v...)
	}
}

func logPrintf(l *log.Logger, format string, v ...interface{}) {
	if l != nil {
		l.Printf(format, v...)
	} else {
		log.Printf(format, v...)
	}
}

func logPrintln(l *log.Logger, v ...interface{}) {
	if l != nil {
		l.Println(v...)
	} else {
		log.Println(v...)
	}
}
