# Introduction

This tool is a modified version of scapy that aims at providing an quick and
efficient pentest tool with RF capabilities.

It includes:

* A modified version of scapy that can leverage GNU Radio to handle a SDR card
* GNU Radio flow graphs (GRC files) we have build that allows full duplex communication
* GNU Radio blocks we have written to handle several protocols



## Supported radio protocols:

* Bluetooth LE (advertising only)
* 802.15.4 (used by Zigbee, Xbee, 6LoWPAN)
* ZWave (European frequency, 868MHz)


# Requirements

You need to have a full working GNU Radio 3.7 installation.

**Note**: You will need to edit GRC files if you are running with GNU Radio 3.7.5+
because they changed the UHD Sink block (there is now 2 inputs, the first one being
for commands instead of samples).

The provided GRC files have been fully tested with an Ettus B210 SDR but they
should work just as fine with any other UHD compatible device.

You can also edit the GRC files to replace UHD Sink/Source blocks by the
corresponding Osmocom blocks. Don't forget to set the parameters correctly.


# Installation

We tried to make the installation as easy as possible.

If you want to install everything, just launch:

`$ ./install.sh`

The script will prompt you for your password to install the tools system-wide
using `sudo` command.

Usage:

`$ ./install.sh [scapy|grc|blocks] ...`


## Options

### scapy
This will install or update scapy installation. This option is useful when you
have added/modified layers and want to make them available in your system

### grc
This will copy all the GRC files into `$HOME/.scapy/radio/` and it will also
convert them automatically into Python files using `grcc` command.

### blocks
This will build all the extra blocks you have written for GNU Radio and install
them.


# Usage

The tool can be launched by using the following command:

`$ scapy-radio`

## Switch between protocol

One in the scapy interactive shell, switching between radio protocols is as
simple as:

` >>> switch_radio_protocol("ZWave")`

You can also specify the radio protocol directly to some "radio-enabled" functions:

` >>> sniff_radio(radio="ZWave")`

## Radio commands

* `switch_radio_protocol(layer, *args, **kargs)`: change the current radio protocol
* `sniffradio(opened_socket=None, radio=None, *args, **kargs)`: works like `sniff()`
* `srradio(pkts, inter=0.1, *args, **kargs)`: works like `sr()`
* `srradio1(pkts, *args, **kargs)`: works like `sr1()`
* `gnuradio_get_vars(*args, **kargs)`: get variables for the running GRC
* `gnuradio_set_vars(host="localhost", port=8080, **kargs)`: set variable for the running GRC
* `gnuradio_start_graph(host="localhost", port=8080)`: resume the running GRC
* `gnuradio_stop_graph(host="localhost", port=8080)`: pause the running GRC


## Reading / Writing PCAP files

The tool allows writing and reading back PCAP files with the usual `scapy` command:

```python
>>> wrpcap("pcap-file.pcap", pkts)
>>> pkts2 = rdpcap("pcap-file.pcap")
```


# Tools

## ZWave
### Automaton\_stop\_alarm.py

This script is a scapy Automaton that will send a *switch off* ZWave packet each times it
listens a *switch on* ZWave packet.

The script has been used to successfully disable a ZWave siren alarm automatically.

### passive\_scan.py

This script intends to passively scan and map ZWave automation network.

