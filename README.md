# dns-monitor

A small DNS traffic monitor written in C. It captures DNS messages either live from a network
interface or offline from a PCAP file, parses them, and prints what it finds. Optionally it can
keep a running list of every domain name it has seen and every domain-to-IP mapping it has
observed in responses.

Built on `libpcap` for capture and `libresolv` (`dn_expand`) for decompressing DNS names.

---

## Features

- Live capture from an interface, or offline analysis of a `.pcap` file
- IPv4 and IPv6 support
- Two output modes: a one-line-per-packet summary, and a verbose mode showing the full DNS message
- Appends every observed domain name to a file (`-d`), without duplicates
- Appends every observed `domain -> IP` translation from A/AAAA answers to a file (`-t`), without duplicates
- Both files are read back on startup, so multiple runs can accumulate into the same file
- Graceful shutdown on `SIGINT`, `SIGTERM` and `SIGQUIT`

## Requirements

- A C compiler (`gcc`) and `make`
- `libpcap` development headers
- `libresolv` (part of glibc on Linux)

## Build

```bash
make
```

This produces the `dns-monitor` binary in the project root. Object files go to `build/`.

## Usage

```
./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]
```

| Option | Description |
| --- | --- |
| `-i <interface>` | Interface to listen on (live capture) |
| `-p <pcapfile>` | PCAP file to read (offline analysis) |
| `-v` | Verbose mode — print the complete DNS message |
| `-d <domainsfile>` | Append every observed domain name to this file |
| `-t <translationsfile>` | Append every observed domain-to-IP translation to this file |
| `-h` | Print help and exit |

`-i` and `-p` are mutually exclusive, and exactly one of them is required.

Only UDP traffic on port 53 is captured — the BPF filter `udp port 53` is applied to the capture
handle.

**Live capture needs elevated privileges:**

```bash
sudo ./dns-monitor -i eth0
```

### Examples

```bash
# Watch DNS traffic on eth0
sudo ./dns-monitor -i eth0

# Analyse a capture file with full detail
./dns-monitor -p capture.pcap -v

# Watch an interface and log domains and translations to files
sudo ./dns-monitor -i eth0 -d domains.txt -t translations.txt
```

## Output

### Default mode

One line per DNS message:

```
2024-11-17 21:28:14 192.168.1.104 -> 8.8.8.8 (Q 1/0/0/1)
2024-11-17 21:28:14 8.8.8.8 -> 192.168.1.104 (R 1/1/0/1)
```

The format is `timestamp src -> dst (direction questions/answers/authority/additional)`, where
direction is `Q` for a query and `R` for a response, and the four numbers are the section counts
from the DNS header.

### Verbose mode (`-v`)

The full message, with each record printed in a zone-file-like format. Records are separated by a
line of `=` characters:

```
Timestamp: 2024-11-17 21:49:57
SrcIP: 127.0.0.1
DstIP: 127.0.0.1
SrcPort: UDP/53
DstPort: UDP/45132
Identifier: 0xF413
Flags: QR=1, OPCODE=0, AA=1, TC=0, RD=1, RA=1, AD=0, CD=0, RCODE=0

[Question Section]
ns1.test.local. IN A

[Answer Section]
ns1.test.local. 604800 IN A 127.0.0.1
====================
```

## Log files

### Domains file (`-d`)

One domain name per line, in the order they were first seen:

```
google.com
ns1.test.local
alias.test.local
```

Names are collected from the question section, from record owner names, and from the RDATA of
NS, CNAME, MX, SOA and SRV records.

### Translations file (`-t`)

One `domain ip` pair per line, taken from A and AAAA records in responses only:

```
google.com 142.250.185.174
ns1.test.local 127.0.0.1
```

Both files are loaded into memory at startup if they already exist, so re-running the program
against the same file will not create duplicate entries.

## Supported record and class types

| Category | Supported |
| --- | --- |
| Record types | A, AAAA, NS, CNAME, SOA, MX, SRV |
| Classes | IN, CS, CH, HS |

Anything else is still counted and its length reported, but the RDATA is not decoded — unknown
types print as `OTHER` and unknown classes as `UNKNOWN`.

## Limitations

- Ethernet only (`DLT_EN10MB`); other link types are rejected
- UDP only — DNS over TCP, DoT and DoH are not handled
- Of the IPv6 extension headers, only Hop-by-Hop, Routing, Destination Options and Fragment are
  skipped; anything else causes the packet to be dropped
- DNS name decompression assumes a message no larger than 512 bytes, so large or EDNS-extended
  responses may be parsed incompletely
- Domain and translation sets are linear-scanned, so very long runs with many unique names will
  slow down

## Project structure

```
src/
  main.c                  entry point, context setup, signal handling
  args.c/.h               command-line parsing
  dns_capture.c/.h        pcap setup, capture loop, IPv4/IPv6 dispatch
  process_dns_packet.c/.h DNS question and resource record parsing
  print_dns.c/.h          output formatting (default and verbose)
  domains.c/.h            domain name set and file logging
  translations.c/.h       domain-to-IP set and file logging
  dns_structures.h        shared structs (context, DNS header)
Makefile
manual.pdf                full project documentation
```

## Documentation

`manual.pdf` contains the full write-up: application design, implementation details for each
parsing stage, and the testing methodology with results.
