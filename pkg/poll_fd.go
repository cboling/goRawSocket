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
	"unsafe"
)

type pollfd struct {
	fd      int
	events  int16
	revents int16
}

func (pfd *pollfd) getPointer() unsafe.Pointer {
	if HostIntSize == 4 {
		// #nosec
		return unsafe.Pointer(&(struct {
			fd      int32
			events  int16
			revents int16
		}{
			int32(pfd.fd),
			pfd.events,
			pfd.revents,
		}))
	} else {
		// #nosec
		return unsafe.Pointer(&(struct {
			fd      int64
			events  int16
			revents int16
		}{
			int64(pfd.fd),
			pfd.events,
			pfd.revents,
		}))
	}
}

func (pfd *pollfd) size() int {
	return HostIntSize + 2*HostShortSize
}
