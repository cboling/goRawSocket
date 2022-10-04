/*
 * Copyright (c) 2022 - present.  Boling Consulting Solutions (bcsw.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rawsocket

import (
	"fmt"
	"syscall"
	"unsafe"
)

func errnoErr(e syscall.Errno, operation string) error {
	switch e {
	case 0:
		return nil
	case syscall.EAGAIN:
		return fmt.Errorf("%v: try again", operation)
	case syscall.EINVAL:
		return fmt.Errorf("%v: invalid argument", operation)
	case syscall.ENOENT:
		return fmt.Errorf("%v: no such file or directory", operation)
	default:
		return fmt.Errorf("%v: Error: %v", operation, e)
	}
}

func bigEndian() (ret bool) {
	var i = 0x1
	// #nosec
	bs := (*[int(unsafe.Sizeof(0))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0

}

func Htons(value uint16) uint16 {
	if bigEndian() {
		return value
	}
	return (value << 8) | (value >> 8)
}

func calculateLargestFrame(ceil uint) uint {
	sz := uint(MinimumFrameSize)
	for sz < ceil {
		sz <<= 1
	}
	// return sz >> 1
	return sz
}
