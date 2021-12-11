# CAPitan

<img src="internal/web/static/images/logo_transparent_background.png" alt="Logo"  />

**CAPitan** is a scriptable web UI based network sniffer, ARP scanner and spoofing build for being lightweight and easy
to config.

## Installation

```shell
go install github.com/shoriwe/CAPitan/cmd/capitan@latest
```

## Preview

To start **CAPitan** in memory mode at `127.0.0.1:8080` execute:

```shell
capitan memory
```

For more options check:

```shell
capitan memory -h
```

```shell
capitan help
```

![login](docs/images/login.PNG)

The default credentials to login in the memory mode are:

Username: `admin`

Password: `admin`

### Network packet capture

#### Listing old captures

<div style="border: 1px solid black;">
    <img src="docs/images/listing-old-captures.PNG" alt="listing-old-captures"/>
</div>

#### Creating new captures

<div style="border: 1px solid black;">
    <img src="docs/images/capture-setup.PNG" alt="starting-capture"  />
</div>

#### Importing pcap files

<div style="border: 1px solid black;">
    <img src="docs/images/import-capture.PNG" alt="starting-capture"  />
</div>

#### Looking at results

##### TCP streams

<div style="border: 1px solid black;">
    <img src="docs/images/tcp-streams-results.PNG" alt="starting-capture"  />
</div>

##### Packets captured

<div style="border: 1px solid black;">
    <img src="docs/images/packets-results.PNG" alt="starting-capture"  />
</div>

##### Topology

<div style="border: 1px solid black;">
    <img src="docs/images/network-topology.PNG" alt="starting-capture"  />
</div>

##### Packets send per host count

<div style="border: 1px solid black;">
    <img src="docs/images/packets-send-per-host.PNG" alt="starting-capture"  />
</div>

##### Layer 4 type count

<div style="border: 1px solid black;">
    <img src="docs/images/layer-4-count.PNG" alt="starting-capture"  />
</div>

##### TCP stream content types

<div style="border: 1px solid black;">
    <img src="docs/images/tcp-stream-type-count.PNG" alt="starting-capture"  />
</div>

### ARP Scanner

##### List old scans

<div style="border: 1px solid black;">
    <img src="docs/images/arp-scan.PNG" alt="starting-capture"  />
</div>

##### Start new scan

<div style="border: 1px solid black;">
    <img src="docs/images/arp-scan-results.PNG" alt="starting-capture"  />
</div>

### ARP Spoofing

<div style="border: 1px solid black;">
    <img src="docs/images/arp-spoof.PNG" alt="starting-capture"  />
</div>

### Documentation

You can check the documentation of the scripting language [plasma](https://shoriwe.github.io/documentation/docs.html).

Then for the scripting functionality of the Network packet sniffer you can check [here]().

For the scripting functionality of the ARP scanner check [here]().

### Important note

The entire application is filled with XSS holes that I'm still patching, so you are advised.
