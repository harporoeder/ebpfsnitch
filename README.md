# ebpfsnitch

ebpfsnitch is a Linux Application Level Firewall based on eBPF and NFQUEUE.
It is inspired by [OpenSnitch](https://github.com/evilsocket/opensnitch), and
[Douane](https://douaneapp.com/), but utilizing modern kernel abstractions,
without a kernel module.

## Disclaimer

This is an experimental project, and is currently not usable. The security
of this application has not been audited by a 3rd party, or even myself. There
are likely mechanisms by which it could be bypassed. Currently the daemon
control socket is unauthenticated, and an attacker could impersonate the
user interface to self authorize.

## Features

ebpfsnitch currently only supports filtering outgoing IPv4 TCP connections,
everything else is allowed through by default. Filtering for ICPM, and UDP
should be supported in the near future. Other protocols may eventually
get blanket authorization support.

A core goal of this project is to integrate well with containerized
applications. If an application is running in a container that container
can be controlled independently of the base system or other containers.

Additionally targeting can occur against specific system users. Blanket
permissions for every instance of Firefox for every user are not required.