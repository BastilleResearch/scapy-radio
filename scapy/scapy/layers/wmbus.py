# -*- coding: utf-8 -*-
## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Airbus DS CyberSecurity, 2014
## Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
## This program is published under a GPLv2 license

"""
Wireless M-Bus.
Implemented against: https://github.com/CBrunsch/scambus
"""

from scapy.packet import *
from scapy.fields import *
import struct


class WMBusManufacturerField(LEShortEnumField):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "2s")

    def i2h(self, pkt, x):
        temp = struct.unpack("<H", x)[0]
        return chr(((temp >> 10) & 0x001F) + 64) + chr(((temp >> 5) & 0x001F) + 64) + chr((temp & 0x001F) + 64)

    def h2i(self, pkt, x):
        tab = [ord(c) - 64 for c in x]
        return struct.pack("<H", (tab[0] << 10) + (tab[1] << 5) + tab[2])


class WMBus(Packet):
    device_types = {
        0x00: 'Other',
        0x01: 'Oil',
        0x02: 'Electricity',
        0x03: 'Gas',
        0x04: 'Head',
        0x05: 'Steam ',
        0x06: 'Warm water (30-90 °C)',
        0x07: 'Water ',
        0x08: 'Heat cost allocator ',
        0x09: 'Compressed air ',
        0x0A: 'Cooling load meter (Volume measured at return temperature: outlet)',
        0x0B: 'Cooling load meter (Volume measured at flow temperature: inlet)',
        0x0C: 'Heat (Volume measured at flow temperature: inlet)',
        0x0D: 'Heat / Cooling load meter',
        0x0E: 'Bus / System component',
        0x0F: 'Unknown medium',
        0x10: 'Reserved for consumption meter',
        0x11: 'Reserved for consumption meter',
        0x12: 'Reserved for consumption meter',
        0x13: 'Reserved for consumption meter',
        0x14: 'Calorific value',
        0x15: 'Hot water (≥ 90 °C)',
        0x16: 'Cold water',
        0x17: 'Dual register (hot/cold) water meter',
        0x18: 'Pressure',
        0x19: 'A/D Converter',
        0x1A: 'Smoke detector',
        0x1B: 'Room sensor (eg temperature or humidity)',
        0x1C: 'Gas detector',
        0x1D: 'Reserved for sensors',
        0x1F: 'Reserved for sensors',
        0x20: 'Breaker (electricity)',
        0x21: 'Valve (gas or water)',
        0x22: 'Reserved for switching devices',
        0x23: 'Reserved for switching devices',
        0x24: 'Reserved for switching devices',
        0x25: 'Customer unit (display device)',
        0x26: 'Reserved for customer units',
        0x27: 'Reserved for customer units',
        0x28: 'Waste water',
        0x29: 'Garbage',
        0x2A: 'Reserved for Carbon dioxide',
        0x2B: 'Reserved for environmental meter',
        0x2C: 'Reserved for environmental meter',
        0x2D: 'Reserved for environmental meter',
        0x2E: 'Reserved for environmental meter',
        0x2F: 'Reserved for environmental meter',
        0x30: 'Reserved for system devices',
        0x31: 'Reserved for communication controller',
        0x32: 'Reserved for unidirectional repeater',
        0x33: 'Reserved for bidirectional repeater',
        0x34: 'Reserved for system devices',
        0x35: 'Reserved for system devices',
        0x36: 'Radio converter (system side)',
        0x37: 'Radio converter (meter side)',
        0x38: 'Reserved for system devices',
        0x39: 'Reserved for system devices',
        0x3A: 'Reserved for system devices',
        0x3B: 'Reserved for system devices',
        0x3C: 'Reserved for system devices',
        0x3D: 'Reserved for system devices',
        0x3E: 'Reserved for system devices',
        0x3F: 'Reserved for system devices'
    }

    _function_codes = {
        0x0: 'SND-NKE',
        0x3: 'SND-UD',
        0x4: 'SND-NR',
        0x6: 'SND-IR',
        0x7: 'ACC-NR',
        0x8: 'ACC-DMD',
        0xA: 'REQ-UD1',
        0xB: 'REQ-UD2'
    }

    _control_information = {
        0x60: 'COSEM Data sent by the Readout device to the meter with long Transport Layer',
        0x61: 'COSEM Data sent by the Readout device to the meter with short Transport Layer',
        0x64: 'Reserved for OBIS-based Data sent by the Readout device to the meter with long Transport Layer',
        0x65: 'Reserved for OBIS-based Data sent by the Readout device to the meter with short Transport Layer',
        0x69: 'EN 13757-3 Application Layer with Format frame and no Transport Layer',
        0x6A: 'EN 13757-3 Application Layer with Format frame and with short Transport Layer',
        0x6B: 'EN 13757-3 Application Layer with Format frame and with long Transport Layer',
        0x6C: 'Clock synchronisation (absolute)',
        0x6D: 'Clock synchronisation (relative)',
        0x6E: 'Application error from device with short Transport Layer',
        0x6F: 'Application error from device with long Transport Layer',
        0x70: 'Application error from device without Transport Layer',
        0x71: 'Reserved for Alarm Report',
        0x72: 'EN 13757-3 Application Layer with long Transport Layer',
        0x73: 'EN 13757-3 Application Layer with Compact frame and long Transport Layer',
        0x74: 'Alarm from device with short Transport Layer',
        0x75: 'Alarm from device with long Transport Layer',
        0x78: 'EN 13757-3 Application Layer without Transport Layer (to be defined)',
        0x79: 'EN 13757-3 Application Layer with Compact frame and no header',
        0x7A: 'EN 13757-3 Application Layer with short Transport Layer',
        0x7B: 'EN 13757-3 Application Layer with Compact frame and short header',
        0x7C: 'COSEM Application Layer with long Transport Layer',
        0x7D: 'COSEM Application Layer with short Transport Layer',
        0x7E: 'Reserved for OBIS-based Application Layer with long Transport Layer',
        0x7F: 'Reserved for OBIS-based Application Layer with short Transport Layer',
        0x80: 'EN 13757-3 Transport Layer (long) from other device to the meter',
        0x81: 'Network Layer data',
        0x82: 'For future use',
        0x83: 'Network Management application',
        0x8A: 'EN 13757-3 Transport Layer (short) from the meter to the other device',
        0x8B: 'EN 13757-3 Transport Layer (long) from the meter to the other device',
        0x8C: 'Extended Link Layer I (2 Byte)',
        0x8D: 'Extended Link Layer II (8 Byte)'
    }
    name = "WMBus"
    fields_desc = [
        ByteField("len", None),
        BitField("control", 0, 4),
        BitEnumField("func", 0, 4, _function_codes),
        WMBusManufacturerField("manuf", 0),
        XLEIntField("addr", 0),
        ByteEnumField("device", 0, device_types),
        ByteField("version", 1),
        ByteEnumField("ci", 0, _control_information)
    ]


class WMBusShortHeader(Packet):
    name = "WMBus ShortHeader"
    _error_code = {
        0: "No error",
        1: "Application busy",
        2: "Any application error",
        3: "Abnormal condition/alarm"
    }
    _access = {
        0: "No access",
        1: "Temporary no access",
        2: "Limited access",
        3: "Unlimited access"
    }
    _encryption = {
        0: "Clear",
        1: "Reserved 1",
        2: "DES-CBC, null IV",
        3: "DES-CBC, non-null IV",
        4: "AES128-CBC, null IV",
        5: "AES128-CBC, non-null IV",
        6: "Reserved for new encryption"
    }
    fields_desc = [
        ByteField("access_nr", 0),
        BitEnumField("error", 0, 2, _error_code),
        FlagsField("status", 0, 6, ["LowPow", "PermErr", "TempErr", "MfgSpec1", "MfgSpec2", "MfgSpec3"]),
        ByteField("config", 0),
        BitEnumField("accessibility", 0, 2, _access),
        BitField("unk", 0, 2),
        BitEnumField("enc", 0, 4, _encryption)
    ]


class WMBusLongHeader(Packet):
    name = "WMBus LongHeader"
    fields_desc = [
        LongField("id", 0),
        WMBusManufacturerField("manuf", 0),
        ByteField("version", 0),
        ByteEnumField("device", 0, WMBus.device_types),
        WMBusShortHeader
    ]


class WMBusDIFList(Packet):
    name = "WMBus DIF"
    fields_desc = []


class WMBusVIFList(Packet):
    name = "WMBus VIF"
    pass


class WMBusDataRecordHeader(Packet):
    name = "WMBus DataRecord Header"
    fields_desc = [
        PacketListField("difs", None, WMBusDIFList),  # TODO: this list grabs all bytes > 0x80 + 1
        PacketListField("vifs", None, WMBusVIFList)  # TODO: see above
    ]


class WMBusDataRecord(Packet):
    name = "WMBus DataRecord"


for i in (0x61, 0x65, 0x6A, 0x6E, 0x74, 0x7A, 0x7B, 0x7D, 0x7F, 0x8A):
    bind_layers(WMBus, WMBusShortHeader, ci=i)
for i in (0x60, 0x64, 0x6B, 0x6F, 0x72, 0x73, 0x75, 0x7C, 0x7E, 0x80, 0x8B):
    bind_layers(WMBus, WMBusLongHeader, ci=i)
for i in (0x69, 0x70, 0x78, 0x79):
    bind_layers(WMBus, WMBusDataRecordHeader)
bind_layers(WMBusLongHeader, WMBusDataRecordHeader)
bind_layers(WMBusShortHeader, WMBusDataRecordHeader)
