package mp2p

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
)

func TestDecl(t *testing.T) {
	addr := net.UDPAddr{IP: NewIPv6(), Port: 1025}
	_, key, _ := ed25519.GenerateKey(rand.Reader)

	d := NewAddressDeclarationPayload(addr, key)
	fmt.Println(d)
	fmt.Println(d.Validate())
}
