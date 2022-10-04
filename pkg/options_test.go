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
package rawsocket_test

import (
	rawsocket "github.com/cboling/goRawSocket/pkg"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOptions_defaults(t *testing.T) {
	sock, err := rawsocket.NewRawSocket("dummy")
	assert.Nil(t, err)
	assert.NotNil(t, sock)

	assert.Equal(t, rawsocket.DefaultFrameSize, sock.MaxPacketSize())
	//assert.Equal(t, rawsocket.DefaultMaxPackets, sock.MaxPackets())
}

func TestOptions_Domain(t *testing.T) {
}

func TestOptions_RxChannel(t *testing.T) {
}

func TestOptions_Version(t *testing.T) {
}

func TestOptions_MaxFrameSize(t *testing.T) {
}

func TestOptions_MaxTotalFrames(t *testing.T) {
}

func TestOptions_RxEnable(t *testing.T) {
}

func TestOptions_TxEnable(t *testing.T) {
}

func TestOptions_VlanRxAdjustEnable(t *testing.T) {
}

func TestOptions_BerkleyPacketFilter(t *testing.T) {
}

func TestOptions_PacketRxFilter(t *testing.T) {
}
