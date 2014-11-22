miniscan
========

A minimal port scanner for TCP and UDP port lists and network environments

It support two calling modes:
- with a port list and a number of hosts
 
  ![](doc/ports.png)

- with a configuration file defining server profiles and network environments:
  
  ![](doc/config.png)

The configuration looks like this:

```
[profiles]
webserver=80
ldap=389,636
domain=u53

[home]
webserver=1stein.org
ldap=10.211.55.8
domain=192.168.2.1,8.8.8.8,8.8.4.4
ldap=192.168.2.4
```

The command line arguments are the following:

```
$ bin/miniscan --help
Usage of bin/miniscan:
  -conf="": load the given configuration file with profiles and environments
  -d=false: print nmap xml output
  -p=[]: a TCP port
  -syn=false: use syn tcp tests (needs root priviledges)
  -u=[]: a UDP port
  -v=false: print nmap output
```

Development
-----------

make

mkdir gonative
cd gonative
export GOPATH=$(pwd)
export PATH=$GOPATH/bin:$PATH
go get github.com/calmh/gonative
go get github.com/mitchellh/gox

cd ../go
export GOPATH=$(pwd)
gox github.com/sttts/miniscan
