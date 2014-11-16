package main

import (
	"fmt"
	"log"
	"github.com/sttts/nmapr"
)

type Port uint

type scanned_port struct {
	port uint
	state string
}

func (p *scanned_port) setState(state string) {
    p.state = state
}

type scanned_host struct {
	name string
	tcp_ports map[uint]scanned_port
	udp_ports map[uint]scanned_port
}

func report_to_scanned_ports(scan_host string, report *nmapr.Report, scanned_ports map[uint]scanned_port) {
	for _, host := range report.Host {
		// find either address or hostname
		found := false
		for _, addr := range host.Address {
			if addr.Addr == scan_host {
				found = true
				break	
			}
		}
		if !found {
			for _, hostname := range host.Hostnames {
				if hostname.Name == scan_host && hostname.Type == "user" {
					found = true
					break
				}
			}
		}
		
		// parse host
		if found {
			for _, port := range host.Ports {
				scanned_ports[port.PortID] = scanned_port{
					port:port.PortID,
					state:port.State.State,
				}
			}	
			return
		}
	}
	
	log.Println(fmt.Sprintf("Cannot find %s in nmap XML report", scan_host))
}