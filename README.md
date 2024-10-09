# net-dup
This very simple program receives datagrams on a given network interface using pcap, adds VXLAN header and resends those datagrams to a specified set of receivers.

The receiving side can configure the VXLAN interface and receive datagrams with no source addresses changed.

This can be useful when duplicating Netflow/IPFIX/sFlow datagrams where it is important to know the address of the sending router or switch.

The utility is similar to the well-known [samplicator](https://github.com/sleinen/samplicator) utility, but instead of spoofing source addresses, it delivers the datagram to the receives via VXLAN "as is".

## Compile

```sh
$ cc -g -Wall -pedantic -Wextra netdup.c -o netdup -lpcap
```

## Use

```sh
$ sudo ./netdup -i eth0 -o 1.2.3.4:4789.12345 -f "udp and port 6543"
```
