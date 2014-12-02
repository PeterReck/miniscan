package main

import (
	"flag"
	"os"
	"github.com/sttts/color"
	"fmt"
	"sort"
)

var debug = false
var verbose = false
var short = false
var use_syn_scan = false

func scan_hosts(hosts []string, tcpPorts []uint, udpPorts []uint) (map[string]scanned_host, error) {
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
		if use_syn_scan {
			method_args = append(method_args, "-sS")	
		} else {
			method_args = append(method_args, "-sT", "--unprivileged")
		}
		report, err := scan(hosts, tcpPorts, method_args)
		if err != nil  {
			return nil, err;
		}
		
		// parse the report
		for _, host := range hosts {
			report_to_scanned_ports(host, report, scanned_hosts[host].tcp_ports)
		}
	}
	
	// do udp scans
	if len(udpPorts) > 0 {
		method_args := []string{"-sU"}
		report, err := scan(hosts, udpPorts, method_args)
		if err != nil {
			return nil, err
		}
		
		// parse the report
		for _, host := range hosts {
			report_to_scanned_ports(host, report, scanned_hosts[host].udp_ports)
		}
	}
	
	return scanned_hosts, nil
}

func tcp_state_color(port uint, state string) (msg color.ColorMsg) {
	long_s := fmt.Sprintf("%d=%s", port, state)
	short_s := fmt.Sprintf("%d", port)
	s := long_s
	if short {
		s = short_s
	}
	switch state {
		case "open":
			return color.BrGreen(s)
		case "closed", "down":
			return color.BrRed(s)
	}
	return color.BrYellow(long_s)	
}

func udp_state_color(port uint, state string) (msg color.ColorMsg) {
	long_s := fmt.Sprintf("u%d=%s", port, state)
	short_s := fmt.Sprintf("u%d", port)
	s := long_s
	if short {
		s = short_s
	}
	switch state {
		case "open", "open|filtered":
			return color.BrGreen(s)
		case "closed", "down":
			return color.BrRed(s)
	}
	return color.BrYellow(long_s)	
}

func print_scanned_hosts(scanned_hosts map[string]scanned_host, explanation string) {
	for _, sh := range scanned_hosts {
		args := [](interface{}){ sh.name + ": " }
		
		// print tcp ports
		sorted_tcp_ports := make([]int, 0, len(sh.tcp_ports))
		for p, _ := range sh.tcp_ports {
			sorted_tcp_ports = append(sorted_tcp_ports, int(p))
		}
		sort.Ints(sorted_tcp_ports)
		for _, p := range sorted_tcp_ports {
			sp := sh.tcp_ports[uint(p)]
			args = append(args, tcp_state_color(sp.port, sp.state), " ")
		}
		
		// print udp ports
		sorted_udp_ports := make([]int, 0, len(sh.udp_ports))
		for p, _ := range sh.udp_ports {
   			sorted_udp_ports = append(sorted_udp_ports, int(p))
		}
		sort.Ints(sorted_udp_ports)
		for _, p := range sorted_udp_ports {
			sp := sh.udp_ports[uint(p)]
			args = append(args, udp_state_color(sp.port, sp.state), " ")
		}
		
		if (explanation!="") {
			args = append(args, color.White("(" + explanation + ")"))
		}
		color.Println(args...)
	}
}

func main() {
	var tcpPorts uintslice
	var udpPorts uintslice

	flag.Var(&tcpPorts, "p", "a TCP port")
	flag.Var(&udpPorts, "u", "a UDP port")
	flag_syn := flag.Bool("syn", false, "use syn tcp tests (needs root priviledges)")
	flag_v := flag.Bool("v", false, "print nmap output")
	flag_d := flag.Bool("d", false, "print nmap xml output")
	flag_s := flag.Bool("s", false, "short output of port, only colors, no state")
	flag_conf := flag.String("conf", "", "load the given configuration file with profiles and environments")
	flag.Parse()
	
	targets := flag.Args()
	verbose = *flag_v
	short = *flag_s
	debug = *flag_d
	use_syn_scan = *flag_syn
	
	if (len(tcpPorts)==0 && len(udpPorts)==0 && *flag_conf=="") || len(targets)==0 {
		if len(targets) > 0 {
			color.Println(color.Red("Error: Either -p, -u or -conf is mandatory"))
    	    println()
    	}    
        flag.PrintDefaults()
    } else if (len(tcpPorts)>0 || len(udpPorts)>0) && *flag_conf!="" {
    	color.Println(color.Red("Error: use port or configuration, not both"))
    	flag.PrintDefaults()
    } else if (*flag_conf!="") {
    	// targets are environments from here on
    	environment_names := targets
    	
    	// parse config file
    	config, err := read_config(*flag_conf)
    	if err!=nil {
    		color.Println(color.Red(err.Error()))
    		os.Exit(2)
    	}
    	
    	// check that all environments are in the config
    	environments := []Environment{}
    	for _, name := range environment_names {
    		env, found := config.environments[name]
			if !found {
				color.Println(color.Red("Error: environment " + name + " not found in configuration"))
				os.Exit(2)
			}
			environments = append(environments, env)
    	}
    	
    	// loop through environments and profiles
    	for _, env := range environments {
    		println("[" + env.name + "]")
    		for profile_name, host_names := range env.hosts_per_profile {
    			tcpPorts := config.profiles[profile_name].tcp_ports
    			udpPorts := config.profiles[profile_name].udp_ports
	    		scanned_hosts, err := scan_hosts(host_names, *tcpPorts, *udpPorts)
    			if (err != nil) {
    				color.Println(color.Red(err.Error()))
    			}
    			print_scanned_hosts(scanned_hosts, profile_name)
    		}
    	}
    } else {
    	// targets are single hosts from here on
    	hosts := targets
    	
    	// pre-fill scanned_hosts with all ports of unknown state
    	scanned_hosts, err := scan_hosts(hosts, tcpPorts, udpPorts)
		if err != nil  {
			color.Println(color.Red(err.Error()))
			os.Exit(1)
		}
		print_scanned_hosts(scanned_hosts, "")
	}	
}
