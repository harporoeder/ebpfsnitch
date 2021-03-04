# eBPFSnitch

eBPFSnitch is a Linux Application Level Firewall based on eBPF and NFQUEUE.
It is inspired by [OpenSnitch](https://github.com/evilsocket/opensnitch), and
[Douane](https://douaneapp.com/), but utilizing modern kernel abstractions,
without a kernel module.

The eBPFSnitch daemon is implemented in C++ 17. The control interface
is implemented in Python 3 utilizing Qt5.

## Disclaimer

This is an experimental project, and is currently not usable. The security
of this application has not been audited by a 3rd party, or even myself. There
are likely mechanisms by which it could be bypassed. Currently the daemon
control socket is unauthenticated, and an attacker could impersonate the
user interface to self authorize.

## Features

eBPFSnitch supports filtering all outgoing IPv4 based protocols
(TCP / UDP / ICMP / etc). Filtering for IPv6, and incoming connections should
be supported in the near future.

A core goal of this project is to integrate well with containerized
applications. If an application is running in a container that container
can be controlled independently of the base system or other containers.

Additionally targeting can occur against specific system users. Blanket
permissions for every instance of Firefox for every user are not required.

## Dependencies

C++:
[pthread](https://man7.org/linux/man-pages/man7/pthreads.7.html),
[libbpf](https://github.com/libbpf/libbpf),
[netfilter_queue](http://www.netfilter.org/projects/libnetfilter_queue/),
[spdlog](https://github.com/gabime/spdlog),
[fmt](https://github.com/fmtlib/fmt),
[nfnetlink](https://www.netfilter.org/projects/libnfnetlink/index.html),
[boost](https://www.boost.org/),
[libmnl](https://www.netfilter.org/projects/libmnl/index.html)

Python: [PyQT5](https://pypi.org/project/PyQt5/)

## System requirements

eBPFSnitch currently requires a recent kernel. The minimum supported version
is Linux 5.8. This required version may be lowered in the future.

## Compilation and quick start instructions

On Arch which is the presently only tested system:

### Setting up the daemon

From the eBPFSnitch repository directory:

```bash
sudo pacman -S clang cmake bpf libnetfilter_queue spdlog git boost libmnl
mkdir build
cd build
cmake ..
make
sudo ./ebpfsnitch
```

### Starting the GUI

From the eBPFSnitch repository directory:

```bash
sudo pacman -S python3 python-pyqt5 
cd ui
python3 main.py
```