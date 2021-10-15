package mp2p

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/crypto/curve25519"
)

const (
	TypeAddressDeclaration uint8 = iota
	TypeSessionInitiation
	TypeSessionData
)

func ParseMessage(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot parse empty message")
	}

	// Session Initiation
	switch data[0] {
	case TypeSessionInitiation:
		return ParseSessionInitiationPayload(data)
	case TypeAddressDeclaration:
		return ParseAddressDeclarationPayload(data)
	case TypeSessionData:
		return ParseSessionDataPayload(data)
	}

	return nil, fmt.Errorf("unsupported protocol %d", data[0])
}

type AddressDeclarationPayload struct {
	Type      uint8
	Port      uint16
	Address   [16]byte
	Src       [32]byte
	Signature [ed25519.SignatureSize]byte
}

func ParseAddressDeclarationPayload(data []byte) (p AddressDeclarationPayload, err error) {
	return p, binary.Read(bytes.NewReader(data), binary.BigEndian, &p)
}

func NewAddressDeclarationPayload(addr net.UDPAddr, key ed25519.PrivateKey) (p AddressDeclarationPayload) {

	p.Type = TypeAddressDeclaration
	p.Port = uint16(addr.Port)

	copy(p.Address[:], addr.IP.To16())
	copy(p.Src[:], key.Public().(ed25519.PublicKey))

	data := p.Bytes()
	copy(p.Signature[:], ed25519.Sign(key, data[:len(data)-ed25519.SignatureSize]))

	return
}

func (p AddressDeclarationPayload) Bytes() (d []byte) {
	w := bytes.NewBuffer(make([]byte, 0, unsafe.Sizeof(p)))
	binary.Write(w, binary.BigEndian, p)
	return w.Bytes()
}

func (p AddressDeclarationPayload) Validate() bool {
	data := p.Bytes()
	return ed25519.Verify(p.Src[:], data[:len(data)-ed25519.SignatureSize], p.Signature[:])
}

type SessionInitiationPayload struct {
	Type       uint8
	SessionID  [16]byte
	Src, Dst   [32]byte
	SessionKey [32]byte
	Signature  [ed25519.SignatureSize]byte
}

func ParseSessionInitiationPayload(data []byte) (p SessionInitiationPayload, err error) {
	return p, binary.Read(bytes.NewReader(data), binary.BigEndian, &p)
}

func NewSessionInitiationPayload(src ed25519.PrivateKey, dst ed25519.PublicKey, sessID []byte) (p SessionInitiationPayload, priv [32]byte, err error) {
	p.Type = TypeSessionInitiation

	if len(sessID) == 16 {
		copy(p.SessionID[:], sessID)
	} else {
		rand.Read(p.SessionID[:])
	}

	copy(p.Src[:], src.Public().(ed25519.PublicKey))
	copy(p.Dst[:], dst)

	// Generate a public key for the diffie helman exchange
	rand.Read(priv[:])
	curve25519.ScalarBaseMult(&p.SessionKey, &priv)

	data := p.Bytes()
	copy(p.Signature[:], ed25519.Sign(src, data[:len(data)-ed25519.SignatureSize]))

	return
}

func (p SessionInitiationPayload) Bytes() []byte {
	w := bytes.NewBuffer(make([]byte, 0, unsafe.Sizeof(p)))
	binary.Write(w, binary.BigEndian, p)
	return w.Bytes()
}

func (p SessionInitiationPayload) Validate() bool {
	data := p.Bytes()
	return ed25519.Verify(p.Src[:], data[:len(data)-ed25519.SignatureSize], p.Signature[:])
}

type SessionDataPayload struct {
	Type      uint8
	SessionID [16]byte
	Nonce     [12]byte
	Data      []byte
}

func ParseSessionDataPayload(data []byte) (p SessionDataPayload, err error) {
	if len(data) < 1+16+12 {
		return p, errors.New("no data")
	}

	r := bytes.NewReader(data)
	p.Type, _ = r.ReadByte()
	r.Read(p.SessionID[:])
	r.Read(p.Nonce[:])

	p.Data = make([]byte, len(data)-(1+16+12))
	r.Read(p.Data)

	return
}

func NewSessionDataPayload(sessKey []byte, sessID [16]byte, data []byte) (p SessionDataPayload) {
	p.Type = TypeSessionData
	p.SessionID = sessID
	rand.Read(p.Nonce[:])

	p.Data = toCipher(sessKey).Seal(nil, p.Nonce[:], data, nil)
	return
}

func (p SessionDataPayload) Decrypt(sessKey []byte) ([]byte, error) {
	return toCipher(sessKey).Open(nil, p.Nonce[:], p.Data, nil)
}

func toCipher(sessKey []byte) cipher.AEAD {
	block, err := aes.NewCipher(sessKey)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	return aesgcm
}

func (p SessionDataPayload) Bytes() []byte {

	w := bytes.NewBuffer(make([]byte, 0, int(unsafe.Sizeof(p))+len(p.Data)))
	w.WriteByte(p.Type)
	w.Write(p.SessionID[:])
	w.Write(p.Nonce[:])
	w.Write(p.Data)

	return w.Bytes()
}
