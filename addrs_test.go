package mp2p

import (
	"fmt"
	"net"
	"testing"
)

func TestAddrs(t *testing.T) {
	// get available network interfaces for
	// this machine
	interfaces, err := net.Interfaces()

	if err != nil {
		fmt.Print(err)
		return
	}

	for _, i := range interfaces {

		fmt.Printf("Name : %v \n", i.Name)
		if i.Flags&net.FlagMulticast == 0 || i.Flags&net.FlagUp == 0 {
			continue
		}

		byNameInterface, err := net.InterfaceByName(i.Name)

		if err != nil {
			fmt.Println(err)
		}

		// Could implement some interface filtering
		fmt.Println(i.MTU, i.HardwareAddr, i.Flags)

		//fmt.Println("Interface by Name : ", byNameInterface)

		addresses, err := byNameInterface.Addrs()

		for k, v := range addresses {

			fmt.Printf("Interface Address #%v : %v, (%s)\n", k, v.String(), v.Network())
			ip, ipnet, err := net.ParseCIDR(v.String())
			if err != nil {
				fmt.Println("  - invalid " + err.Error())
				continue
			}
			if ip.To4() == nil && ip.IsGlobalUnicast() && ipnet != nil {
				fmt.Println(ipnet)
			}
		}
		fmt.Println("------------------------------------")

	}
}
