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

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case syscall.EAGAIN:
		return fmt.Errorf("try again")
	case syscall.EINVAL:
		return fmt.Errorf("invalid argument")
	case syscall.ENOENT:
		return fmt.Errorf("no such file or directory")
	}
	return e
}

func copyFx(dst, src []byte, len uint16) uint16 {
	copy(dst, src)
	return len
}

func bigEndian() (ret bool) {
	var i = 0x1
	bs := (*[int(unsafe.Sizeof(0))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0

}

func Htons(value uint16) uint16 {
	if bigEndian() {
		return value
	}
	return (value << 8) | (value >> 8)
}

type txIndexError int32

func (ie txIndexError) Error() string {
	return fmt.Sprintf("bad format in tx frame %d", ie)
}

func calculateLargestFrame(ceil uint) uint {
	i := uint(MinimumFrameSize)
	for i < ceil {
		i <<= 1
	}
	return i >> 1
}
