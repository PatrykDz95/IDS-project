package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"strings"
	"time"
)

type Rule struct {
	name        string
	description string
	match       func(packet gopacket.Packet) bool
}

var rules = []Rule{
	synFloodRule,
	portScanRule,
	httpSuspiciousRule,
}

var synFloodRule = Rule{
	name:        "SYN Flood",
	description: "Detect SYN flood attack",
	match: func(packet gopacket.Packet) bool {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			return tcp.SYN && !tcp.ACK
		}
		return false
	},
}

var portScanThreshold = 5
var portScanTimeWindow = 10 * time.Second
var portScanTracker = make(map[string][]time.Time)

var portScanRule = Rule{
	name:        "Port Scan",
	description: "Detect port scanning activity",
	match: func(packet gopacket.Packet) bool {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				return false
			}
			ip, _ := ipLayer.(*layers.IPv4)

			srcIP := ip.SrcIP.String()
			timestamp := time.Now()

			if _, exists := portScanTracker[srcIP]; !exists {
				portScanTracker[srcIP] = []time.Time{}
			}

			portScanTracker[srcIP] = append(portScanTracker[srcIP], timestamp)

			var recentAttempts []time.Time
			for _, t := range portScanTracker[srcIP] {
				if timestamp.Sub(t) < portScanTimeWindow {
					recentAttempts = append(recentAttempts, t)
				}
			}
			portScanTracker[srcIP] = recentAttempts

			return len(portScanTracker[srcIP]) > portScanThreshold
		}
		return false
	},
}

var httpSuspiciousPatterns = []string{"sqlmap", "nikto", "dirb"}

var httpSuspiciousRule = Rule{
	name:        "Suspicious HTTP Traffic",
	description: "Detect suspicious HTTP traffic",
	match: func(packet gopacket.Packet) bool {
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload := string(appLayer.Payload())
			for _, pattern := range httpSuspiciousPatterns {
				if strings.Contains(payload, pattern) {
					return true
				}
			}
		}
		return false
	},
}

func analyzePacket(packet gopacket.Packet) {
	for _, rule := range rules {
		if rule.match(packet) {
			alert(rule, packet)
		}
	}
}

func alert(rule Rule, packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		src, dst := networkLayer.NetworkFlow().Endpoints()
		fmt.Printf("Alert: %s - %s\n", rule.name, rule.description)
		fmt.Printf("Source IP: %s, Destination IP: %s\n", src, dst)
	} else {
		fmt.Printf("Alert: %s - %s\n", rule.name, rule.description)
		fmt.Println("Source/Destination IP not available")
	}
}

func main() {
	var device = "\\Device\\"
	var snapshotLen int32 = 1024
	var timeout = 80 * time.Second
	handle, err := pcap.OpenLive(device, snapshotLen, false, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		analyzePacket(packet)
	}
	//devices, err := pcap.FindAllDevs()
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//fmt.Println("Devices found:")
	//for _, device := range devices {
	//	fmt.Printf("Name: %s, Description: %s\n", device.Name, device.Description)
	//	for _, address := range device.Addresses {
	//		fmt.Printf(" - IP address: %s, Subnet mask: %s\n", address.IP, address.Netmask)
	//	}
	//}
}
