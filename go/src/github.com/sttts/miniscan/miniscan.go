package main

import (
	"fmt"
	"log"
	"os/exec"
	"flag"
	"strconv"
	"strings"
)

type intslice []int

func (i *intslice) String() string {
    return fmt.Sprintf("%d", *i)
}

func (i *intslice) Set(value string) error {
    tmp, err := strconv.Atoi(value)
    if err != nil {
        *i = append(*i, -1)
    } else {
        *i = append(*i, tmp)
    }
    return nil
}

func scan(hosts []string, ports []int, method_args []string) {
	// compute nmap arguments
	var portStrings = []string{}
	for _, port := range ports {
		portStrings = append(portStrings, fmt.Sprintf("%d", port))
	}
	var args = []string{"-p", strings.Join(portStrings, ",")}
	args = append(args, method_args...)
	args = append(args, hosts...)
			
	// execute nmap
	log.Println("Exec: nmap " + strings.Join(args, " "))
	output, err := exec.Command("nmap", args...).CombinedOutput()
	if err != nil {
		log.Println(err.Error())
	}
		
	log.Println("Output:\n" + string(output[:]))
}

func main() {
	var tcpPorts intslice
	var udpPorts intslice
	var hosts []string

	flag.Var(&tcpPorts, "p", "a TCP port")
	flag.Var(&udpPorts, "u", "a UDP port")
	flag_sS := flag.Bool("syn", false, "use syn tests (needs root priviledges)")
	flag.Parse()
	hosts = flag.Args()
	
	if (len(tcpPorts)==0 && len(udpPorts)==0) || len(hosts)==0 {
        flag.PrintDefaults()
    } else {
		if len(tcpPorts) > 0 {
			method_args := []string{}
			if *flag_sS {
				method_args = append(method_args, "-sS")	
			}
			scan(hosts, tcpPorts, method_args)
		}
		
		if len(udpPorts) > 0 {
			method_args := []string{"-sU"}
			scan(hosts, udpPorts, method_args)
		}
	}	
}
