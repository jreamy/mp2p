package mp2p

import (
	"crypto/rand"
	"net"
)

func NewIPv6() net.IP {
	ip := make([]byte, net.IPv6len)
	n, err := rand.Reader.Read(ip)
	if n != net.IPv6len || err != nil {
		return nil
	}

	// Set the global transient multicast bits
	ip[0], ip[1] = 0xff, 0x1e
	return ip
}

func NewIPv4() net.IP {
	var ip [4]byte
	rand.Reader.Read(ip[2:])

	ip[0], ip[2] = 0xe0, ip[2]|0xe0
	return ip[:]
}

func GetIface() *net.Interface {
	ifi, err := net.Interfaces()
	if len(ifi) == 0 || err != nil {
		return nil
	}

	return &ifi[0]
}
