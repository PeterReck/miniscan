package main

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"strconv"
	"regexp"
	"github.com/robfig/config"
)

type Profile struct {
	name string
	tcp_ports *[]uint
	udp_ports *[]uint
}

type Environment struct {
	name string
	hosts_per_profile map[string][]string
}

type Config struct {
	profiles map[string]Profile
	environments map[string]Environment
}

func read_config(file_name string) (*Config, error) {
	read_config, err := config.ReadDefault(file_name)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	
	config := Config{
		profiles: make(map[string]Profile),
		environments: map[string]Environment{},
	}
	read_profiles, err := read_config.SectionOptions("profiles")
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	
	// parse profile lines
	for _, profile_name := range read_profiles {
		profile := Profile{name:profile_name, tcp_ports: &[]uint{}, udp_ports: &[]uint{}}
		
		s, _ := read_config.String("profiles", profile_name)
		s = strings.Replace(s, ";", " ", -1)
		s = strings.Replace(s, ",", " ", -1)
		s = strings.Replace(s, "\n", " ", -1)
		ports := strings.Split(s, " ")
		for _, port := range ports {
			if len(port) > 0 {
				// udp?
				udp_matches := regexp.MustCompile("^u([1-9][0-9]*)$").FindStringSubmatch(port)
				if udp_matches != nil {
					int_port, _ := strconv.Atoi(udp_matches[1])
					uint_port := uint(int_port)
					new_udp_ports := append(*profile.udp_ports, uint_port)
					profile.udp_ports = &new_udp_ports
				} else {
					tcp_matches := regexp.MustCompile("^t?([1-9][0-9]*)$").FindStringSubmatch(port)
					if tcp_matches != nil {	
						int_port, _ := strconv.Atoi(tcp_matches[1])
						uint_port := uint(int_port)
						new_tcp_ports := append(*profile.tcp_ports, uint_port)
						profile.tcp_ports = &new_tcp_ports
					} else {
						return nil, errors.New(fmt.Sprintf("Invalid port number '%s'", port))
					}
				}
			}
		}
		
		config.profiles[profile_name] = profile
	}
	
	// parse environments
	for _, section_name := range read_config.Sections() {
		if section_name != "profiles" {
			profile_names, _ := read_config.SectionOptions(section_name)
			hosts_per_profile := map[string][]string{}
			for _, profile_name := range profile_names {
				// check profile
				_, found := config.profiles[profile_name]
				if !found {
					return nil, errors.New(fmt.Sprintf("Invalid profile '%s' in environment '%s'", profile_name, section_name))
				}
				
				// split hosts
				s, _ := read_config.String(section_name, profile_name)
				s = strings.Replace(s, ";", " ", -1)
				s = strings.Replace(s, ",", " ", -1)
				s = strings.Replace(s, "\n", " ", -1)
				host_names := strings.Split(s, " ")
				hosts_per_profile[profile_name] = host_names
			}
			
			config.environments[section_name] = Environment{
				name: section_name,
				hosts_per_profile: hosts_per_profile,
			}
		}
	}
	
	return &config, nil
}