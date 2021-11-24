package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/jreamy/mp2p"
	"github.com/jreamy/mp2p/examples/config"
	"golang.org/x/crypto/curve25519"
)

func main() {
	addrFlag := flag.String("addr", "", "peer address to ping")
	publFlag := flag.String("publ", "", "peer public key")
	ifiFlag := flag.String("ifi", "en0", "network interface to use")
	debug := flag.Bool("v", false, "debug logging")
	verbose := flag.Bool("vv", false, "verbose logging")
	loop := flag.Bool("loop", false, "continue pinging server")
	prefix := flag.Bool("prefix6", false, "use an ipv6 unicast prefixed multicast address")
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

	var ifi *net.Interface
	if *prefix {
		ip, ifi, err = mp2p.NewPrefixedIPv6()
		if err != nil {
			log.Fatalf("failed to generate ipv6 addr: %v", err)
		}
		addr.IP = ip
	} else {
		ifi, err = net.InterfaceByName(*ifiFlag)
		if err != nil {
			log.Println("interfaces include:")
			allIfaces, _ := net.Interfaces()
			for _, ifi := range allIfaces {
				log.Println(" - " + ifi.Name)
			}

			log.Fatalf("network interface invalid: %v", err)
		}
	}

	conn, err := mp2p.NewConn(ifi, addr.IP, addr.Port)
	if err != nil {
		log.Fatalf("failed to intialize client: %v", err)
	}
	defer conn.Close()
	time.Sleep(time.Second)

	fmt.Printf("my addr: %s\nmy publ: %s\n", ip, hex.EncodeToString(key.Public().(ed25519.PublicKey)))

	// Generate the payloads
	addrDecl := mp2p.NewAddressDeclarationPayload(addr, key)
	sessInit, sessSecret, err := mp2p.NewSessionInitiationPayload(key, peerKey, nil)
	if err != nil {
		log.Fatalf("failed to generate session initiation with: %v", err)
	}

	// Write to the peer with a built in retry
	msg, _, err := writeWithRetry(conn, 20, time.Second, func() {
		if _, err := conn.WriteTo(addrDecl.Bytes(), peerAddr); err != nil {
			log.Fatalf("failed to send address declaration with: %v", err)
		}

		if *debug {
			log.Printf("sending session initiation payload")
		} else if *verbose {
			log.Printf("sending session initiation payload %+v", sessInit)
		}

		// Send the session initiation
		if _, err := conn.WriteTo(sessInit.Bytes(), peerAddr); err != nil {
			log.Fatalf("failed to send session initiation with: %v", err)
		}
	})
	if err != nil {
		log.Fatalf("failed with: %v", err)
	}

	if *debug {
		log.Printf("received response payload")
	} else if *verbose {
		log.Printf("received response payload %+v", msg)
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

	send := func() {
		msg, _, err = writeWithRetry(conn, 20, time.Second, func() {
			if *debug {
				log.Printf("sending session data")
			} else if *verbose {
				log.Printf("sending session data %+v", sessData)
			}

			// Send the session data
			if _, err := conn.WriteTo(sessData.Bytes(), peerAddr); err != nil {
				log.Fatalf("failed to send session data with: %v", err)
			}
		})

		if *debug {
			log.Printf("received response payload")
		} else if *verbose {
			log.Printf("received response payload %+v", msg)
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
	if *loop {
		for {
			send()
		}
	} else {
		send()
	}
}

func writeWithRetry(conn mp2p.PacketConn, count int, delay time.Duration, fn func()) (interface{}, []byte, error) {

	done := make(chan bool)
	defer close(done)

	go func() {
		for i := 1; i <= count; i++ {
			fn()
			select {
			case <-time.After(time.Duration(i) * delay):
				continue
			case <-done:
				conn.SetDeadline(time.Now().Add(delay))
				return
			}
		}
	}()

	return read(conn)
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
