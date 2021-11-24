package mp2p

import (
	"crypto/rand"
	"errors"
	"net"
)

// NewPrefixedIPv6 generates a globally routable, unicast-prefixed multicast address with the
// same prefix as the returned net.Interface
func NewPrefixedIPv6() (ip net.IP, ifi *net.Interface, err error) {
	ifis, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, i := range ifis {
		// Filter inactive or non-multicast interfaces
		if i.Flags&net.FlagMulticast == 0 || i.Flags&net.FlagUp == 0 {
			continue
		}

		ifi, err := net.InterfaceByName(i.Name)
		if err != nil {
			continue
		}

		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			_, prefix, _ := net.ParseCIDR(addr.String())
			if ip := NewIPv6FromPrefix(prefix); ip != nil {
				return ip, ifi, nil
			}
		}
	}

	return nil, nil, errors.New("no routable ipv6 multicast interface found")
}

// NewIPv6 generates a random globally routable transient ipv6 multicast address
func NewIPv6() net.IP {
	ip, err := randIP(net.IPv6len)
	if len(ip) != net.IPv6len || err != nil {
		return nil
	}

	// Set the global transient multicast bits
	ip[0], ip[1] = 0xff, 0x1e
	return ip
}

// NewIPv6FromPrefix generates a globally routable unicast prefixed multicast address with the
// same prefix as the given net.IPNet
func NewIPv6FromPrefix(prefix *net.IPNet) net.IP {
	if prefix == nil || !prefix.IP.IsGlobalUnicast() || prefix.IP.To4() != nil {
		return nil
	}

	ip, err := randIP(net.IPv6len)
	if len(ip) != net.IPv6len || err != nil {
		return nil
	}

	_, maskLen := prefix.Mask.Size()

	// Set the global, unicast-prefixed multicast bits
	ip[0], ip[1], ip[2], ip[3] = 0xff, 0x3e, 0x00, byte(maskLen)

	// Copy in the prefix
	if n := copy(ip[4:12], prefix.IP[:8]); n != 8 {
		return nil
	}

	return ip
}

// NewIPv4 generates a random unassigned ipv4 multicast address
func NewIPv4() net.IP {
	ip, err := randIP(net.IPv4len)
	if len(ip) != net.IPv6len || err != nil {
		return nil
	}

	ip[0], ip[2] = 0xe0, ip[2]|0xe0
	return ip[:]
}

// randIP generates a random byte slice of the desired length
func randIP(iplen int) ([]byte, error) {
	ip := make([]byte, iplen)
	n, err := rand.Reader.Read(ip)
	return ip[:n], err
}
