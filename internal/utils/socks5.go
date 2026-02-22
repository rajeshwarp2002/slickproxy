package utils

import "net"

func CreateSocks5Response(tcpAddr *net.TCPAddr) []byte {
	rep := make([]byte, 256)
	rep[0] = 0x05
	rep[1] = 0x00
	rep[2] = 0x00
	rep[3] = 0x01
	ip := tcpAddr.IP.To4()
	copy(rep[4:], ip)
	rep[8] = byte((tcpAddr.Port >> 8) & 0xff)
	rep[9] = byte(tcpAddr.Port & 0xff)
	return rep[:10]
}
func SetIPZone(tcpAddr *net.TCPAddr) {
	if tcpAddr.IP.Equal(tcpAddr.IP.To4()) {
		tcpAddr.Zone = "ip4"
	} else {
		tcpAddr.Zone = "ip6"
	}
}
