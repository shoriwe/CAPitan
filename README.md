# CAPitan

<img src="internal/web/static/images/logo_transparent_background.png" alt="Logo"  />

**CAPitan** is a scriptable web UI based network sniffer, ARP scanner and spoofing build for being lightweight and easy
to config.

## Installation

First install `libpcap` if you are on Linux or `npcap` if your are on windows. Then...

```shell
go install github.com/shoriwe/CAPitan/cmd/capitan@latest
```

## Preview

To start **CAPitan** in memory mode at `127.0.0.1:8080` execute:

```shell
capitan memory
```

Then you can visit it from the url

```
http://127.0.0.1:8080
```

For more options check:

```shell
capitan memory -h
```

```shell
capitan help
```

![login](docs/images/login.png)

The default credentials to login in the memory mode are:

Username: `admin`

Password: `admin`

### Network packet capture

#### Listing old captures

<div style="border: 1px solid black;">
    <img src="docs/images/listing-old-captures.png" alt="listing-old-captures"/>
</div>

#### Creating new captures

<div style="border: 1px solid black;">
    <img src="docs/images/capture-setup.png" alt="starting-capture"  />
</div>

#### Importing pcap files

<div style="border: 1px solid black;">
    <img src="docs/images/import-capture.png" alt="starting-capture"  />
</div>

#### Looking at results

##### TCP streams

<div style="border: 1px solid black;">
    <img src="docs/images/tcp-streams-results.png" alt="starting-capture"  />
</div>

##### Packets captured

<div style="border: 1px solid black;">
    <img src="docs/images/packets-results.png" alt="starting-capture"  />
</div>

##### Topology

<div style="border: 1px solid black;">
    <img src="docs/images/network-topology.png" alt="starting-capture"  />
</div>

##### Packets send per host count

<div style="border: 1px solid black;">
    <img src="docs/images/packets-send-per-host.png" alt="starting-capture"  />
</div>

##### Layer 4 type count

<div style="border: 1px solid black;">
    <img src="docs/images/layer-4-count.png" alt="starting-capture"  />
</div>

##### TCP stream content types

<div style="border: 1px solid black;">
    <img src="docs/images/tcp-stream-type-count.png" alt="starting-capture"  />
</div>

### ARP Scanner

##### List old scans

<div style="border: 1px solid black;">
    <img src="docs/images/arp-scan.png" alt="starting-capture"  />
</div>

##### Start new scan

<div style="border: 1px solid black;">
    <img src="docs/images/arp-scan-results.png" alt="starting-capture"  />
</div>

### ARP Spoofing

<div style="border: 1px solid black;">
    <img src="docs/images/arp-spoof.png" alt="starting-capture"  />
</div>

### Documentation

You can check the documentation of the scripting language [plasma](https://shoriwe.github.io/documentation/docs.html).

Then for the scripting functionality of the Network packet sniffer you can check [here](https://github.com/shoriwe/CAPitan/wiki/Sniffer-scripting).

For the scripting functionality of the ARP scanner check [here](https://github.com/shoriwe/CAPitan/wiki/ARP-scanner-scripting).

### Important note

The entire application is filled with XSS holes that I'm still patching, so you are advised.
