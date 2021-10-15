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

type session struct {
	id   string
	key  []byte
	addr net.Addr
}

func main() {

	ipv4 := flag.Bool("ipv4", false, "use ipv4 address")
	ifiFlag := flag.String("ifi", "en0", "network interface to use")
	flag.Parse()

	ip, key, err := config.GetConfig("server.conf", *ipv4)

	ifi, err := net.InterfaceByName(*ifiFlag)
	if err != nil {
		log.Println("interfaces include:")
		allIfaces, _ := net.Interfaces()
		for _, ifi := range allIfaces {
			log.Println(" - " + ifi.Name)
		}

		log.Fatalf("network interface invalid: %v", err)
	}

	conn, err := mp2p.NewConn(ifi, ip, 1024)
	if err != nil {
		log.Fatalf("failed to intiialize server: %v", err)
	}
	defer conn.Close()

	fmt.Printf("my addr: %s\nmy publ: %s\n", ip, hex.EncodeToString(key.Public().(ed25519.PublicKey)))

	// map of public key -> address
	peers := make(map[string]net.Addr)

	// map of session id -> session key
	sessions := make(map[string]session)

	for {
		data := make([]byte, 1500)
		n, _, err := conn.ReadFrom(data)
		if err != nil {
			log.Printf("failed to read %s with %v", data, err)
			continue
		}

		msg, err := mp2p.ParseMessage(data[:n])
		if err != nil {
			log.Printf("failed to parse message with %v", err)
			continue
		}

		switch x := msg.(type) {
		case mp2p.AddressDeclarationPayload:

			// Check the message signature
			if !x.Validate() {
				log.Printf("address declaration had invalid signature")
				continue
			}

			// General application would be more selective that accepting any peer connection
			// Add the remote address to the list of known addressess
			peers[string(x.Src[:])] = &net.UDPAddr{Port: int(x.Port), IP: net.IP(x.Address[:])}

		case mp2p.SessionInitiationPayload:
			// Check the source is a known peer
			peer, ok := peers[string(x.Src[:])]
			if !ok {
				log.Printf("session initiation by unknown peer")
				continue
			}

			// Check the destination is this node
			if !bytes.Equal(key.Public().(ed25519.PublicKey), x.Dst[:]) {
				log.Printf("session initiation for other node")
				continue
			}

			// Check the message signature
			if !x.Validate() {
				log.Printf("session initiation had invalid signature")
				continue
			}

			// Any session initiation payload coming to the server will not be a response,
			// peer to peer nodes would implement both initial payload and response logic

			// Generate a session payload & key
			resp, priv, err := mp2p.NewSessionInitiationPayload(key, x.Src[:], x.SessionID[:])
			if err != nil {
				log.Printf("failed to generate session initiation response")
				continue
			}

			// Compute & store the diffie hellman session key
			sessID := string(x.SessionID[:])
			sessKey, err := curve25519.X25519(priv[:], x.SessionKey[:])

			sessions[sessID] = session{
				id:   sessID,
				key:  sessKey,
				addr: peer,
			}

			// Respond to the client with their half of the diffie key
			if _, err := conn.WriteTo(resp.Bytes(), peer); err != nil {
				log.Printf("failed to send session initiation response")
				continue
			}

		case mp2p.SessionDataPayload:
			// Check the session is known
			sessID := string(x.SessionID[:])
			sess, ok := sessions[sessID]
			if !ok {
				log.Printf("unknown session id")
				continue
			}

			// Our example server is just going to print incoming requests and then respond
			// with the given message

			data, err := x.Decrypt(sess.key)
			if err != nil {
				log.Printf("failed to decipher with: " + err.Error())
				continue
			}

			fmt.Println(string(data))

			resp := mp2p.NewSessionDataPayload(sess.key, x.SessionID, []byte("Hi this is Jack : )"))
			conn.WriteTo(resp.Bytes(), sess.addr)
		}
	}
}
