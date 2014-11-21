package main

import (
	"fmt"
	"os/exec"
	"os"
	"io/ioutil"	
	"strings"	
	"github.com/sttts/nmapr"
	"github.com/sttts/color"
)

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
	if (verbose || debug) {
		color.Println(color.White("Exec: nmap " + strings.Join(args, " ")))
	}
	output, err := exec.Command("nmap", args...).CombinedOutput()
	if verbose || debug || err != nil {
		color.Println(color.White("Output:\n" + string(output[:])))
	}
	if err != nil {
		color.Println(color.White(err.Error()))
		return nil, err
	}
	
	// print xml output?
	if debug {
		xml_string, _ := ioutil.ReadFile(temp_file.Name())
		color.Println(color.White("XML Output:\n" + string(xml_string[:])))
	}
	
	// parse xml output
	return nmapr.Open(temp_file.Name())
}