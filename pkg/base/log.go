// Copyright EasyStack. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package base

import (
	"fmt"
	"io"
	"path/filepath"
	"runtime"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/klog/v2"
)

// service indicates whether the logging is running in service mode.
var service bool = true

// Log represents a structured log with optional key-value fields.
type Log struct {
	withField  bool   // Indicates if the log has a key-value field
	key, value string // The key-value field for the log
}

// InitializeBinaryLog sets up logging to a file with log rotation.
// If logFilePath is empty, logging is not redirected to a file.
func InitializeBinaryLog(logFilePath string) {
	service = false
	if logFilePath != "" {
		logrus.SetOutput(io.MultiWriter(&lumberjack.Logger{
			Filename:   logFilePath,
			MaxSize:    50, // Megabytes
			MaxBackups: 3,
			MaxAge:     10,
			Compress:   true, // Compression is enabled by default
		}))
	}
}

// withField returns a new log entry with the specified key-value pair.
func withField(key, value string) *logrus.Entry {
	return logrus.WithField(key, value)
}

// NewLog creates a new Log instance without key-value fields.
func NewLog() Log {
	return Log{}
}

// NewLogWithField creates a new Log instance with the specified key-value field.
func NewLogWithField(key, value string) Log {
	return Log{withField: true, key: key, value: value}
}

// Infof logs an informational message with optional formatting.
func (l *Log) Infof(format string, args ...any) {
	if service {
		klog.InfoDepth(1, fmt.Sprintf(format, args...))
	} else {
		if l.withField {
			withField(l.key, l.value).WithField("call", getCaller()).Infof(format, args...)
		} else {
			logrus.WithField("call", getCaller()).Infof(format, args...)
		}
	}
}

// Errorf logs an error message with optional formatting.
func (l *Log) Errorf(format string, args ...any) {
	if service {
		klog.ErrorDepth(1, fmt.Sprintf(format, args...))
	} else {
		if l.withField {
			withField(l.key, l.value).WithField("call", getCaller()).Errorf(format, args...)
		} else {
			logrus.WithField("call", getCaller()).Errorf(format, args...)
		}
	}
}

// Debugf logs a debug message with optional formatting.
func (l *Log) Debugf(format string, args ...any) {
	if service {
		klog.InfofDepth(1, fmt.Sprintf(format, args...))
	} else {
		if l.withField {
			withField(l.key, l.value).WithField("call", getCaller()).Debugf(format, args...)
		} else {
			logrus.WithField("call", getCaller()).Debugf(format, args...)
		}
	}
}

// Warnf logs a warning message with optional formatting.
func (l *Log) Warnf(format string, args ...any) {
	if service {
		klog.WarningDepth(1, fmt.Sprintf(format, args...))
	} else {
		if l.withField {
			withField(l.key, l.value).WithField("call", getCaller()).Warnf(format, args...)
		} else {
			logrus.WithField("call", getCaller()).Warnf(format, args...)
		}
	}
}

// Fatalf logs a fatal error message with optional formatting and then exits the application.
func (l *Log) Fatalf(format string, args ...any) {
	if service {
		klog.FatalDepth(1, fmt.Sprintf(format, args...))
	} else {
		if l.withField {
			withField(l.key, l.value).WithField("call", getCaller()).Fatalf(format, args...)
		} else {
			logrus.WithField("call", getCaller()).Fatalf(format, args...)
		}
	}
}

// Flush flushes any buffered log entries to the output.
func Flush() {
	if service {
		klog.Flush()
	}
}

// getCaller returns a string representation of the caller's file and line number.
func getCaller() string {
	pc, _, _, ok := runtime.Caller(2)
	if ok {
		fn := runtime.FuncForPC(pc)
		file, line := fn.FileLine(pc)
		name := filepath.Base(file)
		return fmt.Sprintf("%s:%d", name, line)
	}
	return ""
}
