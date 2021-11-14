package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/jreamy/mp2p"
	"github.com/jreamy/mp2p/examples/config"
	"golang.org/x/crypto/curve25519"
)

func main() {
	addrFlag := flag.String("addr", "", "peer address to ping")
	publFlag := flag.String("publ", "", "peer public key")
	ifiFlag := flag.String("ifi", "en0", "network interface to use")
	flag.Parse()

	// Parse the command line args for the peer to talk to
	peerIP := net.ParseIP(*addrFlag)
	if peerIP == nil {
		log.Fatalf("failed to parse peer ip: %s", *addrFlag)
	}

	peerAddr := &net.UDPAddr{IP: peerIP, Port: 1024}

	peerKeyBytes, err := hex.DecodeString(*publFlag)
	if len(peerKeyBytes) != ed25519.PublicKeySize || err != nil {
		log.Fatalf("failed to parse peer key: %s", *publFlag)
	}

	peerKey := ed25519.PublicKey(peerKeyBytes)

	// Client configuration
	ip, key, err := config.GetConfig("client.conf", peerIP.To4() != nil)
	addr := net.UDPAddr{IP: ip, Port: 1025}

	ifi, err := net.InterfaceByName(*ifiFlag)
	if err != nil {
		log.Println("interfaces include:")
		allIfaces, _ := net.Interfaces()
		for _, ifi := range allIfaces {
			log.Println(" - " + ifi.Name)
		}

		log.Fatalf("network interface invalid: %v", err)
	}

	conn, err := mp2p.NewConn(ifi, addr.IP, addr.Port)
	if err != nil {
		log.Fatalf("failed to intialize client: %v", err)
	}
	defer conn.Close()

	fmt.Printf("my addr: %s\nmy publ: %s\n", ip, hex.EncodeToString(key.Public().(ed25519.PublicKey)))

	// Send the address declaration
	addrDecl := mp2p.NewAddressDeclarationPayload(addr, key)

	if _, err := conn.WriteTo(addrDecl.Bytes(), peerAddr); err != nil {
		log.Fatalf("failed to send address declaration with: %v", err)
	}

	// Send the session initiation payload
	sessInit, sessSecret, err := mp2p.NewSessionInitiationPayload(key, peerKey, nil)
	if err != nil {
		log.Fatalf("failed to generate session initiation with: %v", err)
	}

	// Send the session initiation
	if _, err := conn.WriteTo(sessInit.Bytes(), peerAddr); err != nil {
		log.Fatalf("failed to send session initiation with: %v", err)
	}

	// Wait for a response
	msg, _, err := read(conn)
	if err != nil {
		log.Fatalf("failed to parse message with %v", err)
	}

	var sessKey []byte

	switch x := msg.(type) {
	case mp2p.SessionInitiationPayload:
		// Check the source the known peer
		if !bytes.Equal(peerKeyBytes, x.Src[:]) {
			log.Fatalf("session initiation response by unknown peer")
		}

		// Check the destination is this node
		if !bytes.Equal(key.Public().(ed25519.PublicKey), x.Dst[:]) {
			log.Fatalf("session initiation response for other node")
		}

		// Check the message signature
		if !x.Validate() {
			log.Fatalf("session initiation response had invalid signature")
		}

		sessKey, err = curve25519.X25519(sessSecret[:], x.SessionKey[:])
		if err != nil {
			log.Fatalf("failed to compute session key")
		}
	default:
		log.Fatalf("failed to receive response from server")
	}

	// Send the server a message
	sessData := mp2p.NewSessionDataPayload(sessKey, sessInit.SessionID, []byte("Hello server, how are you?"))

	// Send the session data
	if _, err := conn.WriteTo(sessData.Bytes(), peerAddr); err != nil {
		log.Fatalf("failed to send session data with: %v", err)
	}

	// Wait for a response
	msg, _, err = read(conn)
	if err != nil {
		log.Fatalf("failed to parse message with %v", err)
	}

	switch x := msg.(type) {
	case mp2p.SessionDataPayload:
		// Check the session id
		if !bytes.Equal(sessInit.SessionID[:], x.SessionID[:]) {
			log.Fatalf("session data had wrong id %s", x.SessionID)
		}

		response, err := x.Decrypt(sessKey)
		if err != nil {
			log.Fatalf("failed to decrypt session data with: %v", err)
		}

		fmt.Println(string(response))
	default:
		log.Fatalf("failed to receive response from server")
	}
}

func read(conn mp2p.PacketConn) (interface{}, []byte, error) {
	data := make([]byte, 1500)
	n, _, err := conn.ReadFrom(data)
	if err != nil {
		return nil, nil, err
	}

	msg, err := mp2p.ParseMessage(data[:n])
	return msg, data, err
}