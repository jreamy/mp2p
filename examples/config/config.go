package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"net"
	"os"

	"github.com/jreamy/mp2p"
)

func GetConfig(filename string, ipv4 bool) (net.IP, ed25519.PrivateKey, error) {
	if _, err := os.Stat(filename); err == nil {
		bin, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, nil, err
		}

		data := readFiledata(bin)
		return data.ip(ipv4), data.Priv[:], nil

	} else if os.IsNotExist(err) {
		data, bin := newFiledata()

		return data.ip(ipv4), data.Priv[:], ioutil.WriteFile(filename, bin, os.ModePerm)
	}

	return nil, nil, errors.New("file lookup failed")
}

type filedata struct {
	IPv4 [4]byte
	IPv6 [16]byte
	Priv [64]byte
}

func (f filedata) ip(v4 bool) net.IP {
	if v4 {
		return f.IPv4[:]
	}

	return f.IPv6[:]
}

func newFiledata() (f filedata, data []byte) {
	ipv4, ipv6 := mp2p.NewIPv4(), mp2p.NewIPv6()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	copy(f.IPv4[:], ipv4)
	copy(f.IPv6[:], ipv6)
	copy(f.Priv[:], priv)

	var w bytes.Buffer
	binary.Write(&w, binary.BigEndian, &f)
	return f, w.Bytes()
}

func readFiledata(data []byte) (f filedata) {
	binary.Read(bytes.NewReader(data), binary.BigEndian, &f)
	return
}
