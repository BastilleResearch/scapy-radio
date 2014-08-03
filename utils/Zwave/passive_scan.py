#!/usr/bin/python2

# Copyright (C) Airbus DS CyberSecurity
# Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay

## This program is free software; you can redistribute it and/or modify it 
## under the terms of the GNU General Public License version 3 as
## published by the Free Software Foundation.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.

from scapy.all import *
from argparse import ArgumentParser
import sys


def display(seen):
    for home_network in seen:
        print("******************* NEW NETWORK *******************")
        print("Homeid: " + str(home_network))
        for dev in seen[home_network]:
            print "Device:		"
            print "\tDevice ID: " + str(dev)
            print "\tTalks to: ",
            print ", ".join([str(x) for x in seen[home_network][dev].send_to])
            print "\tReceives from: ",
            print ", ".join([str(x) for x in seen[home_network][dev].rec_from])
            print "\tCommand available:"
            print os.linesep.join(["\t\t%s" % c for c in _seen[home_network][dev].type])

        print "***************************************************"


class Zwave_device(object):
    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type.add(value)

    @property
    def rec_from(self):
        return self._rec_from

    @rec_from.setter
    def rec_from(self, value):
        self._rec_from.add(value)

    @property
    def send_to(self):
        return self._send_to

    @send_to.setter
    def send_to(self, value):
        self._send_to.add(value)

    def __init__(self):
        self._type = set()
        self._rec_from = set()
        self._send_to = set()


def handle_packets(packet, seen):
    if packet.homeid not in seen:
        print "[+] New Zwave network: " + str(packet.homeid)
        seen[packet.homeid] = dict()
    for dev in (packet.src, packet.dst):
        if dev not in seen[packet.homeid]:
            seen[packet.homeid][dev] = Zwave_device()
        if dev == packet.dst:
            seen[packet.homeid][dev].type = packet[ZWaveReq].get_field('cmd').i2repr(packet, packet.cmd)
            seen[packet.homeid][dev].rec_from = packet.src
        if dev == packet.src:
            seen[packet.homeid][dev].send_to = packet.dst


if __name__ == "__main__":
    # Init Scapy-radio
    parser = ArgumentParser(sys.argv[0])
    parser.add_argument("--count", "-c", dest="count", type=int, default=None,
                        metavar="INT", help="Number of packet to capture")
    parser.add_argument("--timeout", "-t", dest="timeout", type=int, default=None,
                        metavar="INT", help="Stop sniffing after a given time (in seconds)")
    parser.parse_args(sys.argv[1:])

    load_module('gnuradio')

    _seen = dict()
    try:
        sniffradio(radio="Zwave", store=0, count=args.count, timeout=args.timeout,
                   prn=lambda p, se=_seen: handle_packets(p, se),
                   lfilter=lambda x: x.haslayer(ZwaveReq))
    except KeyboardInterrupt:
        pass
    finally:
        display(_seen)
        sys.exit()


