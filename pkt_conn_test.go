package mp2p

import (
	"net"
)

type BuggyConn struct {
	PacketConn

	LoseWrite   func([]byte) bool
	LoseRead    func([]byte) bool
	DoubleWrite func([]byte) bool
	DoubleRead  func([]byte) bool

	reads chan pkt
}

type pkt struct {
	data []byte
	addr net.Addr
}

func NewBuggyConn(c PacketConn) *BuggyConn {
	return &BuggyConn{
		PacketConn: c,
		reads:      make(chan pkt, 1),
	}
}

func (c *BuggyConn) WriteTo(b []byte, dst net.Addr) (n int, err error) {
	if c.LoseWrite != nil && c.LoseWrite(b) {
		return len(b), nil
	}

	if c.DoubleWrite != nil && c.DoubleWrite(b) {
		c.PacketConn.WriteTo(b, dst)
	}

	return c.PacketConn.WriteTo(b, dst)
}

func (c *BuggyConn) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	var buf []byte
	select {
	case pkt := <-c.reads:
		return cp(pkt.data, b), pkt.addr, nil
	default:
		buf = make([]byte, len(b), cap(b))
		n, src, err = c.PacketConn.ReadFrom(buf)
	}

	if c.LoseRead != nil && c.LoseRead(buf) {
		return c.PacketConn.ReadFrom(b)
	}

	if c.DoubleRead != nil && c.DoubleRead(buf) {
		c.reads <- pkt{data: buf, addr: src}
	}

	return cp(buf, b), src, err
}

func cp(buf, out []byte) int {
	if len(buf) > cap(out) {
		copy(out, buf[:cap(out)])
		return cap(out)
	}

	copy(out, buf)
	return len(buf)
}
