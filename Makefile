all: build build/nmap.exe build/nmap build/miniscan.exe build/miniscan64.exe build/miniscan build/miniscan64 build/mac-miniscan build/miniscan.zip build/miniscan.tar.gz

SHELL = /bin/bash

WIN32_VERSION := 5.50
# everything later has a libsvn_client dependency due to nmap-update
LINUX_VERSION := 5.51.3-1

WIN32_ZIP = nmap-$(WIN32_VERSION)-win32.zip
LINUX_RPM = nmap-$(LINUX_VERSION).x86_64.rpm
RPM2CPIO = $(shell if which rpm2cpio &>/dev/null; then echo rpm2cpio; else echo rpm2cpio.pl; fi)

.PHONY: go_build clean

clean:
	rm -f $(WIN32_ZIP) $(LINUX_RPM)
	rm -rf build
	rm -f go/miniscan_*
	rm -rf gonative

# downloads
$(WIN32_ZIP): 
	wget http://nmap.org/dist/$(WIN32_ZIP)
build/nmap.exe: $(WIN32_ZIP)
	unzip -d build -j $(WIN32_ZIP) nmap-$(WIN32_VERSION)/nmap.exe nmap-$(WIN32_VERSION)/libeay32.dll nmap-$(WIN32_VERSION)/ssleay32.dll
	touch build/nmap.exe

$(LINUX_RPM):
	wget http://nmap.org/dist/$(LINUX_RPM)
build/nmap: $(LINUX_RPM)
	$(RPM2CPIO) $(LINUX_RPM) | cpio -ivd ./usr/bin/nmap
	mv usr/bin/nmap build
	rmdir usr/bin usr

build:
	mkdir -p build

gonative:
	mkdir -p gonative
	cd gonative && \
	export GOPATH=$$(pwd) && \
	go get github.com/calmh/gonative && \
	bin/gonative -version=1.3.3 -platforms='windows_386 linux_amd64 darwin_amd64 windows_amd64'

go_build:
	cd go && \
	export GOPATH=$$(pwd) && export PATH=$$GOPATH/bin:$$PATH && \
	go get -fix github.com/sttts/miniscan && \
	go get github.com/mitchellh/gox && \
	gox -osarch='windows/amd64 windows/386 linux/amd64 darwin/amd64' github.com/sttts/miniscan

build/example.conf: example.conf
	cp example.conf build

build/README.txt: README.md
	cp README.md build/README.txt

build/miniscan.zip: build build/miniscan.exe build/miniscan64.exe build/nmap.exe build/example.conf build/README.txt
	cd build && zip miniscan.zip nmap.exe miniscan*.exe *.dll *.conf README.txt

build/miniscan.tar.gz: build build/miniscan64 build/nmap build/example.conf
	cd build && tar -cvzf miniscan.tar.gz miniscan64 nmap example.conf README.txt

build/miniscan.exe: build go_build
	cp go/miniscan_windows_386.exe build/miniscan.exe

build/miniscan64.exe: build go_build
	cp go/miniscan_windows_amd64.exe build/miniscan64.exe

build/miniscan: build go_build
	cp go/miniscan_linux_386 build/miniscan

build/miniscan64: build go_build
	cp go/miniscan_linux_amd64 build/miniscan64

build/mac-miniscan: build go_build
	cp go/miniscan_darwin_amd64 build/mac-miniscan
