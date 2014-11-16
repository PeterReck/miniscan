package main

import (
	"fmt"
	"flag"
)

var debug = false
var verbose = false

func main() {
	var tcpPorts uintslice
	var udpPorts uintslice
	var hosts []string

	flag.Var(&tcpPorts, "p", "a TCP port")
	flag.Var(&udpPorts, "u", "a UDP port")
	flag_sS := flag.Bool("syn", false, "use syn tests (needs root priviledges)")
	flag_v := flag.Bool("v", false, "print nmap output")
	flag_d := flag.Bool("d", false, "print nmap xml output")
	flag.Parse()
	
	hosts = flag.Args()
	verbose = *flag_v
	debug = *flag_d
	
	if (len(tcpPorts)==0 && len(udpPorts)==0) || len(hosts)==0 {
        flag.PrintDefaults()
    } else {
    	// pre-fill scanned_hosts with all ports of unknown state
    	scanned_hosts := make(map[string]scanned_host)
    	for _, host := range hosts {
    		x := scanned_host{
    			name:host,
    			tcp_ports:make(map[uint]scanned_port),
    			udp_ports:make(map[uint]scanned_port),
    		}
    		for _, p := range tcpPorts {
    			x.tcp_ports[p] = scanned_port{port:p, state:"unknown"}
    		}
    		for _, p := range udpPorts {
    			x.udp_ports[p] = scanned_port{port:p, state:"unknown"}
    		}
    		scanned_hosts[host] = x
    	}
    	
    	// do tcp scans
		if len(tcpPorts) > 0 {
			method_args := []string{}
			if *flag_sS {
				method_args = append(method_args, "-sS")	
			}
			report, err := scan(hosts, tcpPorts, method_args)
			
			// parse the report
			if err == nil {
				for _, host := range hosts {
					report_to_scanned_ports(host, report, scanned_hosts[host].tcp_ports)
				}
			}
		}
		
		// do udp scans
		if len(udpPorts) > 0 {
			method_args := []string{"-sU"}
			report, err := scan(hosts, udpPorts, method_args)
			
			// parse the report
			if err == nil {
				for _, host := range hosts {
					report_to_scanned_ports(host, report, scanned_hosts[host].udp_ports)
				}
			}
		}
		
		// print the result
		for _, sh := range scanned_hosts {
			s := ""
			for _, sp := range sh.tcp_ports {
				s = s + fmt.Sprintf("%d=%s ", sp.port, sp.state)
			}
			for _, sp := range sh.udp_ports {
				s = s + fmt.Sprintf("u%d=%s ", sp.port, sp.state)
			}
			println(sh.name + ": " + s)
		}
	}	
}
