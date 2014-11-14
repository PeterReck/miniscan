miniscan
========

A minimal port scanner for TCP and UDP port lists and network environments

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
