## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Airbus DS CyberSecurity
## Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
## This program is published under a GPLv2 license

"""
Wireless Z-Wave.
"""

from scapy.packet import *
from scapy.fields import *
import struct

_COMMAND_CLASS = {
    0x00: "NO_OPERATION",
    0x20: "BASIC",
    0x21: "CONTROLLER_REPLICATION",
    0x22: "APPLICATION_STATUS",
    0x23: "ZIP_SERVICES",
    0x24: "ZIP_SERVER",
    0x25: "SWITCH_BINARY",
    0x26: "SWITCH_MULTILEVEL",
    0x27: "SWITCH_ALL",
    0x28: "SWITCH_TOGGLE_BINARY",
    0x29: "SWITCH_TOGGLE_MULTILEVEL",
    0x2A: "CHIMNEY_FAN",
    0x2B: "SCENE_ACTIVATION",
    0x2C: "SCENE_ACTUATOR_CONF",
    0x2D: "SCENE_CONTROLLER_CONF",
    0x2E: "ZIP_CLIENT",
    0x2F: "ZIP_ADV_SERVICES",
    0x30: "SENSOR_BINARY",
    0x31: "SENSOR_MULTILEVEL",
    0x32: "METER",
    0x33: "ZIP_ADV_SERVER",
    0x34: "ZIP_ADV_CLIENT",
    0x35: "METER_PULSE",
    0x3C: "METER_TBL_CONFIG",
    0x3D: "METER_TBL_MONITOR",
    0x3E: "METER_TBL_PUSH",
    0x38: "THERMOSTAT_HEATIN",
    0x40: "THERMOSTAT_MODE",
    0x42: "THERMOSTAT_OPERATING_STATE",
    0x43: "THERMOSTAT_SETPOINT",
    0x44: "THERMOSTAT_FAN_MODE",
    0x45: "THERMOSTAT_FAN_STATE",
    0x46: "CLIMATE_CONTROL_SCHEDULE",
    0x47: "THERMOSTAT_SETBACK",
    0x4C: "DOOR_LOCK_LOGGING",
    0x4E: "SCHEDULE_ENTRY_LOCK",
    0x50: "BASIC_WINDOW_COVERING",
    0x51: "MTP_WINDOW_COVERING",
    0x60: "MULTI_CHANNEL_V2",
    0x61: "MULTI_INSTANCE",
    0x62: "DOOR_LOCK",
    0x63: "USER_CODE",
    0x70: "CONFIGURATION",
    0x71: "ALARM",
    0x72: "MANUFACTURER_SPECIFIC",
    0x73: "POWERLEVEL",
    0x75: "PROTECTION",
    0x76: "LOCK",
    0x77: "NODE_NAMING",
    0x7A: "FIRMWARE_UPDATE_MD",
    0x7B: "GROUPING_NAME",
    0x7C: "REMOTE_ASSOCIATION_ACTIVATE",
    0x7D: "REMOTE_ASSOCIATION",
    0x80: "BATTERY",
    0x81: "CLOCK",
    0x82: "HAIL",
    0x84: "WAKE_UP",
    0x85: "ASSOCIATION ",
    0x86: "VERSION",
    0x87: "INDICATOR",
    0x88: "PROPRIETARY",
    0x89: "LANGUAGE ",
    0x8A: "TIME ",
    0x8B: "TIME_PARAMETERS",
    0x8C: "GEOGRAPHIC_LOCATION",
    0x8D: "COMPOSITE",
    0x8E: "MULTI_INSTANCE_ASSOCIATION",
    0x8F: "MULTI_CMD ",
    0x90: "ENERGY_PRODUCTION ",
    0x91: "MANUFACTURER_PROPRIETARY",
    0x92: "SCREEN_MD",
    0x93: "SCREEN_ATTRIBUTES",
    0x94: "SIMPLE_AV_CONTROL",
    0x95: "AV_CONTENT_DIRECTORY_MD",
    0x96: "AV_RENDERER_STATUS",
    0x97: "AV_CONTENT_SEARCH_MD",
    0x98: "SECURITY",
    0x99: "AV_TAGGING_MD ",
    0x9A: "SIP_CONFIGURATION",
    0x9B: "ASSOCIATION_COMMAND_CONFIGURATION",
    0x9C: "SENSOR_ALARM ",
    0x9D: "SILENCE_ALARM",
    0x9E: "MARK",
    0xF0: "NON_INTEROPERABLE"
}


### Layer ###
class BaseZWave(Packet):
    name = "ZWave"
    fields_desc = [
        XIntField("homeid", 0x161f498),
        XByteField("src", 1),
        BitField("routed", 0, 1),
        BitField("ackreq", 1, 1),
        BitField("lowpower", 0, 1),
        BitField("speedmodified", 0, 1),
        BitField("headertype", 0, 4),
        BitField("reserved", 0, 1),
        BitField("beam_control", 0, 2),
        BitField("reserved", 0, 1),
        BitField("seqn", 1, 4),
        XByteField("length", None),
        XByteField("dst", 0x02),
    ]

    def post_build(self, p, pay):
        # Switch payload and CRC
        crc = p[-1]
        p = p[:-1] + pay
        if self.length is None:
            p = p[:7] + chr((len(p) + 1) & 0xff) + p[8:]
        p += crc if self.crc is not None else chr(reduce(lambda x, y: x ^ ord(y), p, 0xff))
        return p

    def hashret(self):
        return struct.pack("!L", self.homeid)

    def answers(self, other):
        return self.src == other.dst and self.dst == other.src
        #return self.payload.answers(other.payload)


class ZWaveAck(BaseZWave):
    name = "ZWaveAck"
    fields_desc = [
        BaseZWave,
        XByteField("crc", None)
    ]


class ZWaveReq(BaseZWave):
    name = "ZWaveReq"
    fields_desc = [
        BaseZWave,
        ByteEnumField("cmd", 0, _COMMAND_CLASS),
        XByteField("crc", None)
    ]

    def pre_dissect(self, s):
        return s[:10] + s[-1] + s[10:-1]


class ZWaveSwitchBin(Packet):
    name = "ZWaveSwitchBin"
    fields_desc = [
        ByteEnumField("switchcmd", 0, {1: "SWITCH", 2: "REQ_STATE", 3: "STATE"}),
        ByteEnumField("val", 0, {0: "OFF", 0xff: "ON"})
    ]	


class ZWaveSensBin(Packet):
    name = "ZWaveSensBin"
    fields_desc = [
        ByteEnumField("senscmd", 0, {2: "REQ_STATE", 3: "SENSOR_STATE"}),
        ByteEnumField("val", 0, {0: "OFF", 0xff: "ON"})
    ]	


def ZWave(_pkt=None, *args, **kargs):
    if _pkt is not None:
        if len(_pkt) == 0xa:
            return ZWaveAck(_pkt, *args, **kargs)
    return ZWaveReq(_pkt, *args, **kargs)

bind_layers(ZWaveReq, ZWaveSwitchBin, cmd=0x25)
bind_layers(ZWaveReq, ZWaveSensBin,   cmd=0x30)

