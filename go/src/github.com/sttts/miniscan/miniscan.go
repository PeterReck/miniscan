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

var OPEN_STATUS = map[string][]string {
	"udp": []string {"open", "open|filtered"},
	"tcp": []string {"open"},
}

var CLOSED_STATUS = map[string][]string {
	"udp": []string {"closed", "down"},
	"tcp": []string {"closed", "down"},
}

func contains(s []string, e string) bool {
    for _, a := range s { if a == e { return true } }
    return false
}

func state_color(protocol string, port uint, state string) (msg color.ColorMsg) {
	s := fmt.Sprintf("%d", port)
	if protocol == "udp" {
		s = "u" + s
	}
	if contains(OPEN_STATUS[protocol], state) {
		return color.BrGreen(s)
	} else if contains(CLOSED_STATUS[protocol], state) {
		return color.BrRed(s)
	}
	return color.BrYellow(s)
}

func print_scanned_hosts(scanned_hosts map[string]scanned_host, explanation string) {
	prefix := ""
	if explanation != "" {
		color.Println(explanation + ":")
		prefix = "  "
	}
	for _, sh := range scanned_hosts {
		args := [](interface{}){ prefix + sh.name + ": " }
		
		// sort and check tcp ports
		all_open := true
		sorted_tcp_ports := make([]int, 0, len(sh.tcp_ports))
		for p, _ := range sh.tcp_ports {
			if ! contains(OPEN_STATUS["tcp"], sh.tcp_ports[p].state) { 
				all_open = false
			} 
			sorted_tcp_ports = append(sorted_tcp_ports, int(p))
		}
		sort.Ints(sorted_tcp_ports)
		
		// sort and check udp ports
		sorted_udp_ports := make([]int, 0, len(sh.udp_ports))
		for p, _ := range sh.udp_ports {
			if ! contains(OPEN_STATUS["udp"], sh.udp_ports[p].state) { 
				all_open = false
			} 
   			sorted_udp_ports = append(sorted_udp_ports, int(p))
		}
		sort.Ints(sorted_udp_ports)
		
		// print
		if all_open || short {
			// print a one-liner, all ports are open
			for _, p := range sorted_tcp_ports {
				sp := sh.tcp_ports[uint(p)]
				args = append(args, state_color("tcp", sp.port, sp.state), " ")
			}
			for _, p := range sorted_udp_ports {
				sp := sh.udp_ports[uint(p)]
				args = append(args, state_color("udp", sp.port, sp.state), " ")
			}
			color.Println(args...)
		} else {
			//
			// print multi-line, one line per state
			//
			color.Println(args...)
			
			// find states
			used_states := map[string]bool{}
			port_strings_by_state := make(map[string][](interface{}))
			for _, p := range sorted_tcp_ports {
				sp := sh.tcp_ports[uint(p)]
				used_states[sp.state] = true
			}
			for _, p := range sorted_udp_ports {
				sp := sh.udp_ports[uint(p)]
				used_states[sp.state] = true
			}
			sorted_states := make([]string, 0)
			for state, _ := range used_states {
				sorted_states = append(sorted_states, state)
			}
			sort.Strings(sorted_states)
			for _, state := range sorted_states {
				empty_port_string_list := [](interface{}){"    ", state, ": "}
				port_strings_by_state[state] = empty_port_string_list 
			}
			
			// register ports for states
			for _, p := range sorted_tcp_ports {
				sp := sh.tcp_ports[uint(p)]
				port_strings_by_state[sp.state] = append(port_strings_by_state[sp.state], state_color("tcp", sp.port, sp.state), " ")
			}
			for _, p := range sorted_udp_ports {
				sp := sh.udp_ports[uint(p)]
				port_strings_by_state[sp.state] = append(port_strings_by_state[sp.state], state_color("udp", sp.port, sp.state), " ")
			}
			// print lines
			for _, state := range sorted_states {
				color.Println(port_strings_by_state[state]...)
			}
		}
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
	flag_s := flag.Bool("s", false, "short output of port, only colors, no state, all in one line")
	flag_conf := flag.String("conf", "", "load the given configuration file with profiles and environments")
	flag.Parse()
	
	targets := flag.Args()
	verbose = *flag_v
	debug = *flag_d
	short = *flag_s
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
