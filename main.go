package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

func main() {
	var device = "\\Device\\"
	var snapshotLen int32 = 1024
	var timeout = 30 * time.Second
	handle, err := pcap.OpenLive(device, snapshotLen, false, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		analyzePacket(packet)
	}
}

func analyzePacket(packet gopacket.Packet) {
	// Detect SYN flood attack
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			fmt.Println("Detected potential SYN flood attack")
		}
	}
}

// read all devices
//devices, err := pcap.FindAllDevs()
//if err != nil {
//log.Fatal(err)
//}
//
//fmt.Println("Devices found:")
//for _, device := range devices {
//fmt.Printf("Name: %s, Description: %s\n", device.Name, device.Description)
//for _, address := range device.Addresses {
//fmt.Printf(" - IP address: %s, Subnet mask: %s\n", address.IP, address.Netmask)
//}
//}
