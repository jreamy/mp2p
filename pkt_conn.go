package mp2p

import (
	"errors"
	"net"
	"strconv"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type PacketConn interface {
	WriteTo(b []byte, dst net.Addr) (n int, err error)
	ReadFrom(b []byte) (n int, src net.Addr, err error)
	Close() error
	Group() net.Addr
}

func NewConn(ifi *net.Interface, group net.IP, port int) (PacketConn, error) {
	if group.To4() != nil {
		return NewIPv4Conn(ifi, group, port)
	}

	return NewIPv6Conn(ifi, group, port)
}

func NewIPv4Conn(ifi *net.Interface, group net.IP, port int) (p PacketConn, err error) {
	if ifi, err = getIfi(ifi); err != nil {
		return nil, err
	}

	ipGroup := &net.UDPAddr{IP: group, Port: port}
	c, err := net.ListenPacket("udp4", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}

	pkt := ipv4.NewPacketConn(c)
	if err := pkt.JoinGroup(ifi, ipGroup); err != nil {
		c.Close()
		return nil, err
	}

	if err := pkt.SetMulticastTTL(255); err != nil {
		c.Close()
		return nil, err
	}

	if err := pkt.SetTTL(255); err != nil {
		c.Close()
		return nil, err
	}

	return &ipv4Conn{
		PacketConn: pkt,
		ifi:        ifi,
		group:      ipGroup,
	}, nil
}

func NewIPv6Conn(ifi *net.Interface, group net.IP, port int) (p PacketConn, err error) {
	if ifi, err = getIfi(ifi); err != nil {
		return nil, err
	}

	ipGroup := &net.UDPAddr{IP: group, Port: port}
	c, err := net.ListenPacket("udp6", "[::]:"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}

	pkt := ipv6.NewPacketConn(c)
	if err := pkt.JoinGroup(ifi, ipGroup); err != nil {
		c.Close()
		return nil, err
	}

	if err := pkt.SetMulticastHopLimit(255); err != nil {
		c.Close()
		return nil, err
	}

	if err := pkt.SetHopLimit(255); err != nil {
		c.Close()
		return nil, err
	}

	return &ipv6Conn{
		PacketConn: pkt,
		ifi:        ifi,
		group:      ipGroup,
	}, nil
}

// ipv4Conn is an IPv4 implementation of PacketConn
type ipv4Conn struct {
	*ipv4.PacketConn
	ifi   *net.Interface
	group *net.UDPAddr
}

func (i *ipv4Conn) WriteTo(b []byte, dst net.Addr) (n int, err error) {
	wcm := &ipv4.ControlMessage{IfIndex: i.ifi.Index, TTL: 255}
	return i.PacketConn.WriteTo(b, wcm, dst)
}
func (i *ipv4Conn) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	n, _, src, err = i.PacketConn.ReadFrom(b)
	return
}

func (i *ipv4Conn) Close() error {
	i.LeaveGroup(i.ifi, i.group)
	return i.PacketConn.Close()
}

func (i *ipv4Conn) Group() net.Addr {
	return i.group
}

// ipv4Conn is an IPv6 implementation of PacketConn
type ipv6Conn struct {
	*ipv6.PacketConn
	ifi   *net.Interface
	group *net.UDPAddr
}

func (i *ipv6Conn) WriteTo(b []byte, dst net.Addr) (n int, err error) {
	wcm := &ipv6.ControlMessage{TrafficClass: 0xe0, HopLimit: 255, IfIndex: i.ifi.Index}
	return i.PacketConn.WriteTo(b, wcm, dst)
}
func (i *ipv6Conn) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	n, _, src, err = i.PacketConn.ReadFrom(b)
	return
}

func (i *ipv6Conn) Close() error {
	i.LeaveGroup(i.ifi, i.group)
	return i.PacketConn.Close()
}

func (i *ipv6Conn) Group() net.Addr {
	return i.group
}

func getIfi(ifi *net.Interface) (*net.Interface, error) {
	if ifi != nil {
		return ifi, nil
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	if len(interfaces) < 1 {
		return nil, errors.New("no net interfaces found")
	}

	return &interfaces[0], nil
}
