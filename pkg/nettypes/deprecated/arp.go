package deprecated

import (
	"fmt"
	"github.com/cboling/goRawSocket/pkg/nettypes"
	"net"

	"github.com/cboling/goRawSocket/pkg/inet"
)

type ARPOperation uint16

const (
	Request = ARPOperation(0x01)
	Reply   = ARPOperation(0x02)
)

func (ao ARPOperation) String() string {
	switch ao {
	case 0x01:
		return "request"
	case 0x02:
		return "reply"
	}
	return "unknown arp operation"
}

type ARPPacket []byte

func (a ARPPacket) EthType() nettypes.EthType {
	return nettypes.ARP
}

func (a ARPPacket) Bytes() []byte {
	return a
}

func (a ARPPacket) String(indent int) string {
	return fmt.Sprintf(nettypes.padLeft("Htype : %02x\n", "\t", indent), a.HardwareType()) +
		fmt.Sprintf(nettypes.padLeft("Ptype : %s\n", "\t", indent), a.ProtocolType()) +
		fmt.Sprintf(nettypes.padLeft("Hlen  : %d\n", "\t", indent), a.Hlen()) +
		fmt.Sprintf(nettypes.padLeft("Plen  : %d\n", "\t", indent), a.Plen()) +
		fmt.Sprintf(nettypes.padLeft("Oper  : %s\n", "\t", indent), a.Operation()) +
		fmt.Sprintf(nettypes.padLeft("SHA   : %s\n", "\t", indent), a.SHA()) +
		fmt.Sprintf(nettypes.padLeft("SPA   : %s\n", "\t", indent), a.SPA()) +
		fmt.Sprintf(nettypes.padLeft("THA   : %s\n", "\t", indent), a.THA()) +
		fmt.Sprintf(nettypes.padLeft("TPA   : %s\n", "\t", indent), a.TPA())
}

func (a ARPPacket) HardwareType() uint16 {
	return inet.NToHS(a[0:2])
}

func (a ARPPacket) ProtocolType() nettypes.EthType {
	return nettypes.EthType{a[2], a[3]}
}

func (a ARPPacket) Hlen() uint8 {
	return uint8(a[4])
}

func (a ARPPacket) Plen() uint8 {
	return uint8(a[5])
}

func (a ARPPacket) Operation() ARPOperation {
	return ARPOperation(inet.NToHS(a[6:8]))
}

func (a ARPPacket) SHA() net.HardwareAddr {
	return net.HardwareAddr(a[8:14])
}

func (a ARPPacket) SPA() net.IP {
	return net.IP(a[14:18])
}

func (a ARPPacket) THA() net.HardwareAddr {
	return net.HardwareAddr(a[18:24])
}

func (a ARPPacket) TPA() net.IP {
	return net.IP(a[24:28])
}
