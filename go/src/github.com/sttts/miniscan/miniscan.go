package main

import (
	"fmt"
	"log"
	"os/exec"
	"flag"
	"strconv"
	"strings"
	"os"
	"io/ioutil"
	"github.com/sttts/nmapr"
)

var debug = false
var verbose = false

type Port uint
type uintslice []uint

func (i *uintslice) String() string {
    return fmt.Sprintf("%d", *i)
}

func (i *uintslice) Set(value string) error {
    tmp, err := strconv.Atoi(value)
    if err != nil {
        *i = append(*i, 0)
    } else {
        *i = append(*i, uint(tmp))
    }
    return nil
}

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

func scan(hosts []string, ports []uint, method_args []string) (*nmapr.Report, error) {
	// temporary file for xml output
	temp_file, err := ioutil.TempFile(os.TempDir(), "prefix")
	defer os.Remove(temp_file.Name())
	
	// compute nmap arguments
	var portStrings = []string{}
	for _, port := range ports {
		portStrings = append(portStrings, fmt.Sprintf("%d", port))
	}
	var args = []string{"-p", strings.Join(portStrings, ",")}
	args = append(args, method_args...)
	args = append(args, "-n", "-oX", temp_file.Name())
	args = append(args, hosts...)
			
	// execute nmap
	log.Println("Exec: nmap " + strings.Join(args, " "))
	output, err := exec.Command("nmap", args...).CombinedOutput()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	if verbose || debug {
		log.Println("Output:\n" + string(output[:]))
	}
	
	// print xml output?
	if debug {
		xml_string, _ := ioutil.ReadFile(temp_file.Name())
		log.Println("XML Output:\n" + string(xml_string[:]))
	}
	
	// parse xml output
	return nmapr.Open(temp_file.Name())
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
