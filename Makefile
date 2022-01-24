export MAGEFILE_VERBOSE=true
export MAGEFILE_CACHE=
export MAGEFILE_DEBUG=
export MAGEFILE_GOCMD=
export MAGEFILE_IGNOREDEFAULT=

all: bin

kernel: #clean
	mage bpf:kernels

bin:
	rm -f ~/src/conntracct/build/bpf/acct/*
	mage bpf:build
	mage build

run:
	sudo ~/src/conntracct/build/conntracct ct

prepare:
	sudo ./setup-dev.sh

kill:
	 sudo killall -9 conntracct

clean:
	mage bpf:clean
#	rm -f ~/src/conntracct/build/bpf/acct/3.10.0.o
#	rm -f ~/src/conntracct/build/bpf/acct/4.18.0.o
