all: build/nmap.exe build/nmap

WIN32_VERSION := 6.47

# everything later has a libsvn_client dependency due to nmap-update
LINUX_VERSION := 5.51.3-1

WIN32_ZIP = nmap-$(WIN32_VERSION)-win32.zip
LINUX_RPM = nmap-$(LINUX_VERSION).x86_64.rpm
RPM2CPIO=$(shell if which rpm2cpio.pl &>/dev/null; then echo rpm2cpio.pl; else echo rpm2cpio; fi)

clean:
	rm -f $(WIN32_ZIP) $(LINUX_RPM)
	rm -rf build

# downloads
$(WIN32_ZIP): 
	wget http://nmap.org/dist/$(WIN32_ZIP)
build/nmap.exe: $(WIN32_ZIP)
	unzip -d build -j -f $(WIN32_ZIP) nmap-$(WIN32_VERSION)/nmap.exe

$(LINUX_RPM):
	wget http://nmap.org/dist/$(LINUX_RPM)
build/nmap: $(LINUX_RPM)
	$(RPM2CPIO) $(LINUX_RPM) | cpio -ivd usr/bin/nmap
	mv usr/bin/nmap build
	rmdir usr/bin usr
