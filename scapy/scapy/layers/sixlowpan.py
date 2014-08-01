## Copyright (C) Cesar A. Bernardini <mesarpe@gmail.com>
## Intern at INRIA Grand Nancy Est
## This program is published under a GPLv2 license
"""

This implementation follows the next documents:
    * Transmission of IPv6 Packets over IEEE 802.15.4 Networks
    * Compression Format for IPv6 Datagrams in Low Power and Lossy
      networks (6LoWPAN): draft-ietf-6lowpan-hc-15
    * RFC 4291

6LoWPAN Protocol Stack
======================

                            |-----------------------|
Application                 | Application Protocols |
                            |-----------------------|
Transport                   |   UDP      |   TCP    |
                            |-----------------------|
Network                     |          IPv6         | (Only IPv6)
                            |-----------------------|
                            |         LoWPAN        | (in the middle between network and data link layer)
                            |-----------------------|
Data Link Layer             |   IEEE 802.15.4 MAC   |
                            |-----------------------|
Physical                    |   IEEE 802.15.4 PHY   |
                            |-----------------------|

The Internet Control Message protocol v6 (ICMPv6) is used for control
messaging.

Adaptation between full IPv6 and the LoWPAN format is performed by routers at
the edge of 6LoWPAN islands.

A LoWPAN support addressing; a direct mapping between the link-layer address
and the IPv6 address is used for achieving compression.



Known Issues:
    * Unimplemented context information
    * Next header compression techniques

"""

import socket
import struct

from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteField, HiddenField, BitEnumField, Field, BitFieldLenField, XShortField, FlagsField, ConditionalField

from scapy.layers.inet6 import IPv6, IP6Field, ICMPv6EchoRequest
from scapy.layers.inet import UDP

from dot15d4 import Dot15d4, Dot15d4Data, Dot15d4FCS, dot15d4AddressField

from scapy.route6 import *


LINK_LOCAL_PREFIX = "\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

class LoWPAN_TraficClassField(BitField):
    def __init__(self, name, default, size, length_of=None, count_of=None, adjust=lambda pkt,x:x):
        BitFieldLenField.__init__(self, name, default, size, length_of, count_of, adjust)

class IP6FieldLenField(IP6Field):
    def __init__(self, name, default, size, length_of=None, count_of=None, adjust=lambda pkt,x:x):
        IP6Field.__init__(self, name, default)
        self.length_of=length_of
        self.count_of=count_of
        self.adjust=adjust
    def addfield(self, pkt, s, val):
        """Add an internal value  to a string"""
        l = self.length_of(pkt)
        if l == 0:  return s
        internal = self.i2m(pkt,val)[-l:]
        #print "addfield", l, internal.encode('hex')
        return s+struct.pack("!%ds"%l, internal)
    def getfield(self, pkt, s):
        l = self.length_of(pkt)
        assert l >= 0 and l <=16
        if l <= 0:
            return s,""
        #print "getfield", l, s[:l].encode('hex')
        return s[l:], self.m2i(pkt,"\x00"*(16-l) + s[:l])

class BitVarSizeField(BitField):
    def __init__(self, name, default, calculate_length = None):
        BitField.__init__(self, name, default, 0)
        self.length = calculate_length
        
    def addfield(self, pkt, s, val):
        self.size = self.length(pkt)
        return BitField.addfield(self, pkt, s, val)
    def getfield(self, pkt, s):
        self.size = self.length(pkt)
        return BitField.getfield(self, pkt, s)

class SixLoWPANAddrField(Field):
    """Special field to store 6LoWPAN addresses

    6LoWPAN Addresses have a variable length depending on other parameters.
    This special field allows to save them, and encode/decode no matter which
    encoding parameters they have.
    """
    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of=length_of
        self.adjust=adjust
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        return lhex(self.i2h(pkt,x))
    def h2i(self, pkt, x):
        """Convert human value to internal value"""
        if type(x) == int:
            return 0
        elif type(x) == str:
            return Field.h2i(self, pkt, x)
    def i2h(self, pkt, x):
        """Convert internal value to human value"""
        Field.i2h(self, pkt, x)
    def m2i(self, pkt, x):
        """Convert machine value to internal value"""
        return Field.m2i(self, pkt, x)
    def i2m(self, pkt, x):
        """Convert internal value to machine value"""
        return Field.i2m(self, pkt, x)
    def any2i(self, pkt, x):
        """Try to understand the most input values possible and make an internal value from them"""
        return self.h2i(pkt, x)
    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.length_of(pkt) == 8:
            return s + struct.pack(self.fmt[0]+"B", val)
        if self.length_of(pkt) == 16:
            return s + struct.pack(self.fmt[0]+"H", val)
        if self.length_of(pkt) == 32:
            return s + struct.pack(self.fmt[0]+"2H", val) #TODO: fix!
        if self.length_of(pkt) == 48:
            return s + struct.pack(self.fmt[0]+"3H", val) #TODO: fix!
        elif self.length_of(pkt) == 64:
            return s + struct.pack(self.fmt[0]+"Q", val)
        elif self.length_of(pkt) == 128:
            #TODO: FIX THE PACKING!!
            return s + struct.pack(self.fmt[0]+"16s", str(val))
        else:
            return s
    def getfield(self, pkt, s):
        if self.length_of(pkt) == 8:
            return s[1:], self.m2i(pkt, struct.unpack(self.fmt[0]+"B", s[:1])[0])
        elif self.length_of(pkt) == 16:
            return s[2:], self.m2i(pkt, struct.unpack(self.fmt[0]+"H", s[:2])[0])
        elif self.length_of(pkt) == 32:
            return s[4:], self.m2i(pkt, struct.unpack(self.fmt[0]+"2H", s[:2], s[2:4])[0])
        elif self.length_of(pkt) == 48:
            return s[6:], self.m2i(pkt, struct.unpack(self.fmt[0]+"3H", s[:2], s[2:4], s[4:6])[0])
        elif self.length_of(pkt) == 64:
            return s[8:], self.m2i(pkt, struct.unpack(self.fmt[0]+"Q", s[:8])[0])
        elif self.length_of(pkt) == 128:
            return s[16:], self.m2i(pkt, struct.unpack(self.fmt[0]+"16s", s[:16])[0])



class LoWPANUncompressedIPv6(Packet):
    fields_desc = [
        BitField("__type", 0x0, 8)
    ]
    
    def guess_payload_class(self, payload):
        # super SWITCH depending on reserved and type
        if self.__type == LoWPANUncompressedIPv6:
            return IPv6(payload)

class LoWPANMesh(Packet):
    name = "6LoWPAN Mesh Packet"
    fields_desc = [
        HiddenField(BitField("__reserved", 0x2, 2)),
        BitEnumField("__v", 0x0, 1, [False, True]),
        BitEnumField("__f", 0x0, 1, [False, True]),
        BitField("__hopsLeft", 0x0, 4),
        ConditionalField(
            SixLoWPANAddrField("_sourceAddr", 0x0, length_of=lambda pkt: pkt.__v and 2 or 8),
            lambda pkt: source_addr_mode2(pkt) != 0
        ),
        ConditionalField(
            SixLoWPANAddrField("_destinyAddr", 0x0, length_of=lambda pkt: pkt.__f and 2 or 8),
            lambda pkt: destiny_addr_mode(pkt) != 0
        ),
    ]

    def guess_payload_class(self, payload):
        # check first 2 bytes if they are ZERO it's not a 6LoWPAN packet
        pass
        
###############################################################################
# Fragmentation
#
# Section 5.3 - September 2007
###############################################################################

class LoWPANFragmentationFirst(Packet):
    name = "6LoWPAN First Fragmentation Packet"
    fields_desc = [
        HiddenField(BitField("__reserved", 0x18, 5)),
        BitField("datagramSize", 0x0, 11),
        XShortField("datagramTag", 0x0),
    ]
    
    def guess_payload_class(self, payload):
        return LoWPAN_IPHC

class LoWPANFragmentationSubsequent(Packet):
    name = "6LoWPAN Subsequent Fragmentation Packet"
    fields_desc = [
        HiddenField(BitField("__reserved", 0x1C, 5)),
        BitField("datagramSize", 0x0, 11),
        XShortField("datagramTag", 0x0), #TODO: change default value, should be a random one
        ByteField("datagramOffset", 0x0), #VALUE PRINTED IN OCTETS, wireshark does in bits (128 bits == 16 octets)
    ]

IPHC_DEFAULT_VERSION = 6
IPHC_DEFAULT_TF = 0
IPHC_DEFAULT_FL = 0

def source_addr_mode2(pkt):
    """source_addr_mode

    This function depending on the arguments returns the amount of bits to be
    used by the source address.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.sac == 0x0:
        if pkt.sam == 0x0:      return 16
        elif pkt.sam == 0x1:    return 8
        elif pkt.sam == 0x2:    return 2
        elif pkt.sam == 0x3:    return 0
    else:
        if pkt.sam == 0x0:      return 0
        elif pkt.sam == 0x1:    return 8
        elif pkt.sam == 0x2:    return 2
        elif pkt.sam == 0x3:    return 0

def destiny_addr_mode(pkt):
    """destiny_addr_mode

    This function depending on the arguments returns the amount of bits to be
    used by the destiny address.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.m == 0 and pkt.dac == 0:
        if pkt.dam == 0x0:      return 16
        elif pkt.dam == 0x1:    return 8
        elif pkt.dam == 0x2:    return 2
        else:                   return 0
    elif pkt.m == 0 and pkt.dac == 1:
        if pkt.dam == 0x0:      raise Exception('reserved')
        elif pkt.dam == 0x1:    return 8
        elif pkt.dam == 0x2:    return 2
        else:                   return 0
    elif pkt.m == 1 and pkt.dac == 0:
        if pkt.dam == 0x0:      return 16
        elif pkt.dam == 0x1:    return 6
        elif pkt.dam == 0x2:    return 4
        elif pkt.dam == 0x3:    return 1
    elif pkt.m == 1 and pkt.dac == 1:
        if pkt.dam == 0x0:      return 6
        elif pkt.dam == 0x1:    raise Exception('reserved')
        elif pkt.dam == 0x2:    raise Exception('reserved')
        elif pkt.dam == 0x3:    raise Exception('reserved')

def nhc_port(pkt):
    if not pkt.nh:
        return 0, 0
    if pkt.header_compression & 0x3 == 0x3:
        return 4, 4
    elif pkt.header_compression & 0x2 == 0x2:
        return 8, 16
    elif pkt.header_compression & 0x1 == 0x1:
        return 16, 8
    else:
        return 16, 16

def pad_trafficclass(pkt):
    """
    This function depending on the arguments returns the amount of bits to be
    used by the padding of the traffic class.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.tf == 0x0:          return 4
    elif pkt.tf == 0x1:        return 2
    elif pkt.tf == 0x2:        return 0
    else:                      return 0

def flowlabel_len(pkt):
    """
    This function depending on the arguments returns the amount of bits to be
    used by the padding of the traffic class.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.tf == 0x0:          return 20
    elif pkt.tf == 0x1:        return 20
    else:                      return 0

def tf_lowpan(pkt):
    if pkt.tf == 0:
        return 32
    elif pkt.tf == 1:
        return 24
    elif pkt.tf == 2:
        return 8
    else:
        return 0

def tf_last_attempt(pkt):
    if pkt.tf == 0:
        return 2, 6, 4, 20
    elif pkt.tf == 1:
        return 2, 0, 2, 20
    elif pkt.tf == 2:
        return 2, 6, 0, 0
    else:
        return 0, 0 ,0 ,0

class LoWPAN_IPHC(Packet):
    """6LoWPAN IPv6 header compressed packets

    It follows the implementation of draft-ietf-6lowpan-hc-15.
    """
    # the LOWPAN_IPHC encoding utilizes 13 bits, 5 dispatch type
    name = "LoWPAN IP Header Compression Packet"
    fields_desc = [
        #dispatch
        HiddenField(BitField("__reserved", 0x03, 3)),
        BitField("tf", 0x0, 2),
        BitEnumField("nh", 0x0, 1, [False, True]),
        BitField("hlim", 0x0, 2),
        BitEnumField("cid", 0x0, 1, [False, True]),
        BitEnumField("sac", 0x0, 1, [False, True]),
        BitField("sam", 0x0, 2),
        BitEnumField("m", 0x0, 1, [False, True]),
        BitEnumField("dac", 0x0, 1, [False, True]),
        BitField("dam", 0x0, 2),
        ConditionalField(
            ByteField("__contextIdentifierExtension", 0x0), #
            lambda pkt: pkt.cid == 0x1
        ),
        #TODO: THIS IS WRONG!!!!!
        BitVarSizeField("tc_ecn", 0, calculate_length = lambda pkt: tf_last_attempt(pkt)[0]),
        BitVarSizeField("tc_dscp", 0, calculate_length = lambda pkt: tf_last_attempt(pkt)[1]),
        BitVarSizeField("__padd", 0, calculate_length = lambda pkt: tf_last_attempt(pkt)[2]),
        BitVarSizeField("flowlabel", 0, calculate_length = lambda pkt: tf_last_attempt(pkt)[3]),

        #NH
        ConditionalField(
            ByteField("_nhField", 0x0), #
            lambda pkt: not pkt.nh
        ),
        #HLIM: Hop Limit: if it's 0
        ConditionalField(
            ByteField("_hopLimit", 0x0),
            lambda pkt: pkt.hlim == 0x0
        ),
        IP6FieldLenField("sourceAddr", "::", 0, length_of=source_addr_mode2),
        IP6FieldLenField("destinyAddr", "::", 0, length_of=destiny_addr_mode), #problem when it's 0
        
        # LoWPAN_UDP Header Compression ########################################
        # TODO: IMPROVE!!!!!
        ConditionalField(
            FlagsField("header_compression", 0, 8, ["A", "B", "C", "D", "E", "C", "PS", "PD"]),
            lambda pkt: pkt.nh
        ),
        ConditionalField(
            BitFieldLenField("udpSourcePort", 0x0, 16, length_of = lambda pkt: nhc_port(pkt)[0]),
            #ShortField("udpSourcePort", 0x0),
            lambda pkt: pkt.nh and pkt.header_compression & 0x2 == 0x0
        ),
        ConditionalField(
            BitFieldLenField("udpDestinyPort", 0x0, 16, length_of = lambda pkt: nhc_port(pkt)[1]),
            lambda pkt: pkt.nh and pkt.header_compression & 0x1 == 0x0
        ),
        ConditionalField(
            XShortField("udpChecksum", 0x0),
            lambda pkt: pkt.nh and pkt.header_compression & 0x4 == 0x0
        ),
        
    ]
    
    def post_dissect(self, data):
        """dissect the IPv6 package compressed into this IPHC packet.

        The packet payload needs to be decompressed and depending on the
        arguments, several convertions should be done.
        """
        #print "post_dissect"
        
        #uncompress payload
        packet = IPv6()
        packet.version = IPHC_DEFAULT_VERSION
        packet.tc, packet.fl = self._getTrafficClassAndFlowLabel()
        if not self.nh: packet.nh = self._nhField
        #HLIM: Hop Limit
        if self.hlim == 0:
            packet.hlim = self._hopLimit
        elif self.hlim == 0x1:
            packet.hlim = 1
        elif self.hlim == 0x2:
            packet.hlim = 64
        else:
            packet.hlim = 255
        #TODO: Payload length can be inferred from lower layers from either the
        #6LoWPAN Fragmentation header or the IEEE802.15.4 header
        
        packet.src = self.decompressSourceAddr(packet)
        packet.dst = self.decompressDestinyAddr(packet)
        
        if self.nh == 1:
            # The Next Header field is compressed and the next header is
            # encoded using LOWPAN_NHC
            
            udp = UDP()
            if self.header_compression & 0x4 == 0x0:
                udp.chksum = self.udpChecksum
            
            s, d = nhc_port(self)
            if s == 16:
                udp.sport = self.udpSourcePort
            elif s == 8:
                udp.sport = 0xF000 + s
            elif s == 4:
                udp.sport = 0xF0B0 + s
            if d == 16:
                udp.dport = self.udpDestinyPort
            elif d == 8:
                udp.dport = 0xF000 + d
            elif d == 4:
                udp.dport = 0xF0B0 + d
            
            packet.payload = udp/data
            data = str(packet)
        #else self.nh == 0 not necesary
        elif self._nhField & 0xE0 == 0xE0: # IPv6 Extension Header Decompression
            raise Exception('Unimplemented: IPv6 Extension Header decompression')
        else:
            packet.payload = data
            data = str(packet)
        
        return Packet.post_dissect(self, data)
        
    def decompressDestinyAddr(self, packet):
        #print "decompressDestinyAddr"
        try:
            tmp_ip = socket.inet_pton(socket.AF_INET6, self.destinyAddr)
        except socket.error:
            tmp_ip = "\x00"*16
        
        
        if self.m == 0 and self.dac == 0:
            if self.dam == 0:
                pass
            elif self.dam == 1:
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + tmp_ip[-8:]
            elif self.dam == 2:
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + "\x00\x00\x00\xff\xfe\x00" + tmp_ip[-2:]
            """else: #self.dam == 3
                raise Exception('Unimplemented')"""
            
        elif self.m == 0 and self.dac == 1:
            if self.dam == 0:
                raise Exception('Reserved')
            elif self.dam == 0x3:
                underlayer = self.underlayer
                while underlayer != None and isinstance(underlayer, SixLoWPAN):
                    underlayer = underlayer.underlayer
                if type(underlayer) == Dot15d4Data:
                    if underlayer.underlayer.fcf_destaddrmode == 3:
                        tmp_ip = LINK_LOCAL_PREFIX[0:8] + struct.pack(">Q", underlayer.dest_addr)
                        #Turn off the bit 7.
                        tmp_ip = tmp_ip[0:8] + struct.pack("B", (struct.unpack("B", tmp_ip[8])[0] ^ 0x2)) + tmp_ip[9:16]
                    elif underlayer.underlayer.fcf_destaddrmode == 2:
                        tmp_ip = LINK_LOCAL_PREFIX[0:8] + \
                            "\x00\x00\x00\xff\xfe\x00" + \
                            struct.pack(">Q", underlayer.dest_addr)
                else:
                    payload = packet.payload
                    #Most of the times, it's necessary the IEEE 802.15.4 data to extract this address
                    raise Exception('Unimplemented: IP Header is contained into IEEE 802.15.4 frame, in this case it\'s not available.')
        elif self.m == 1 and self.dac == 0:
            if self.dam == 0:
                raise Exception("unimplemented")
            elif self.dam == 1:
                tmp_ip = "\xff" + tmp_ip[16 - destiny_addr_mode(self)] + \
                    "\x00"*9 + tmp_ip[-5:]
            elif self.dam == 2:
                tmp_ip = "\xff" + tmp_ip[16 - destiny_addr_mode(self)] + \
                    "\x00"*11 + tmp_ip[-3:]
            else: # self.dam == 3:
                tmp_ip = "\xff\x02" + "\x00"*13 + tmp_ip[-1:]
        elif self.m == 1 and self.dac == 1:
            if self.dam == 0x0:
                raise Exception("Unimplemented: I didnt understand the 6lowpan specification")
            else: #all the others values
                raise Exception("Reserved value by specification.")
                
        
        self.destinyAddr = socket.inet_ntop(socket.AF_INET6, tmp_ip)
        return self.destinyAddr
    
    def compressSourceAddr(self, ipv6):
        #print "compressSourceAddr"
        tmp_ip = socket.inet_pton(socket.AF_INET6, ipv6.src)
        
        if self.sac == 0:
            if self.sam == 0x0:
                tmp_ip = tmp_ip
            elif self.sam == 0x1:
                tmp_ip = tmp_ip[8:16]
            elif self.sam == 0x2:
                tmp_ip = tmp_ip[14:16]
            else: #self.sam == 0x3:
                pass
        else: #self.sac == 1
            if self.sam == 0x0:
                tmp_ip = "\x00"*16
            elif self.sam == 0x1:
                tmp_ip = tmp_ip[8:16]
            elif self.sam == 0x2:
                tmp_ip = tmp_ip[14:16]
        
        self.sourceAddr = socket.inet_ntop(socket.AF_INET6, "\x00"*(16-len(tmp_ip)) + tmp_ip)
        return self.sourceAddr
    
    def compressDestinyAddr(self, ipv6):
        #print "compressDestinyAddr"
        tmp_ip = socket.inet_pton(socket.AF_INET6, ipv6.dst)
        
        if self.m == 0 and self.dac == 0:
            if self.dam == 0x0:
                tmp_ip = tmp_ip
            elif self.dam == 0x1:
                tmp_ip = "\x00"*8 + tmp_ip[8:16]
            elif self.dam == 0x2:
                tmp_ip = "\x00"*14 + tmp_ip[14:16]
        elif self.m == 0 and self.dac == 1:
            if self.dam == 0x1:
                tmp_ip = "\x00"*8 + tmp_ip[8:16]
            elif self.dam == 0x2:
                tmp_ip = "\x00"*14 + tmp_ip[14:16]
        elif self.m == 1 and self.dac == 0:
            if self.dam == 0x1:
                tmp_ip = "\x00"*10 + tmp_ip[1] + tmp_ip[11:16]
            elif self.dam == 0x2:
                tmp_ip = "\x00"*12 + tmp_ip[1] + tmp_ip[13:16]
            elif self.dam == 0x3:
                tmp_ip = "\x00"*15 + tmp_ip[15:16]
        elif self.m == 1 and self.dac == 1:
            raise Exception('Unimplemented')
        
        #print len(tmp_ip)
        #print "M: %d, DAC: %d, DAM: %d, %s"%(self.m, self.dac, self.dam, tmp_ip.encode('hex'))
        self.destinyAddr = socket.inet_ntop(socket.AF_INET6, tmp_ip)
    
    def decompressSourceAddr(self, packet):
        #print "decompressSourceAddr"
        try:
            tmp_ip = socket.inet_pton(socket.AF_INET6, self.sourceAddr)
        except socket.error, e:
            tmp_ip = "\x00"*16
        
        
        if self.sac == 0:
            if self.sam == 0x0:
                pass
            elif self.sam == 0x1:
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + tmp_ip[16 - source_addr_mode2(self):16]
            elif self.sam == 0x2:
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + "\x00\x00\x00\xff\xfe\x00" + \
                    tmp_ip[16 - source_addr_mode2(self):16]
            else: # self.sam == 0x3 EXTRACT ADDRESS FROM Dot15d4
                underlayer = self.underlayer
                if underlayer != None:
                    while underlayer != None and isinstance(underlayer, SixLoWPAN):
                        underlayer = underlayer.underlayer
                    assert type(underlayer) == Dot15d4Data
                    if underlayer.underlayer.fcf_srcaddrmode == 3:
                        tmp_ip = LINK_LOCAL_PREFIX[0:8] + struct.pack(">Q", underlayer.src_addr)
                        #Turn off the bit 7.
                        tmp_ip = tmp_ip[0:8] + struct.pack("B", (struct.unpack("B", tmp_ip[8])[0] ^ 0x2)) + tmp_ip[9:16]
                    elif underlayer.underlayer.fcf_srcaddrmode == 2:
                        tmp_ip = LINK_LOCAL_PREFIX[0:8] + \
                            "\x00\x00\x00\xff\xfe\x00" + \
                            struct.pack(">Q", underlayer.src_addr)
                else:
                    payload = packet.payload
                    #Most of the times, it's necessary the IEEE 802.15.4 data to extract this address
                    raise Exception('Unimplemented: IP Header is contained into IEEE 802.15.4 frame, in this case it\'s not available.')
        else: #self.sac == 1:
            if self.sam == 0x0:
                pass
            elif self.sam == 0x2:
                #TODO: take context IID
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + "\x00\x00\x00\xff\xfe\x00" + \
                    tmp_ip[16 - source_addr_mode2(self):16]
            elif self.sam == 0x3:
                tmp_ip = LINK_LOCAL_PREFIX[0:8] + "\x00"*8 #TODO: CONTEXT ID
            else:
                raise Exception('Unimplemented')
        
        self.sourceAddr = socket.inet_ntop(socket.AF_INET6, tmp_ip)
        return self.sourceAddr
    
    def guess_payload_class(self, payload):
        return IPv6

    def do_build(self):
        #print "do_build"
        assert type(self.payload) == IPv6
        ipv6 = self.payload
        
        self._reserved = 0x03
        
        # NEW COMPRESSION TECHNIQUE!
        # a ) Compression Techniques
        
        # 1. Set Traffic Class
        if self.tf == 0x0:
            self.tc_ecn = ipv6.tc >> 6
            self.tc_dscp = ipv6.tc & 0x3F
            self.flowlabel = ipv6.fl
        elif self.tf == 0x1:
            self.tc_ecn = ipv6.tc >> 6
            self.flowlabel = ipv6.fl
        elif self.tf == 0x2:
            self.tc_ecn = ipv6.tc >> 6
            self.tc_dscp = ipv6.tc & 0x3F
        else: #self.tf == 0x3:
            pass # no field is set
        
        # 2. Next Header
        if self.nh == 0x0:
            self.nh = 0#ipv6.nh
        else: #self.nh == 0x1
            raise Exception('Unimplemented: The Next Header field is compressed and the next header is encoded using LOWPAN_NHC, which is discussed in Section 4.1.')
        
        # 3. HLim
        if self.hlim == 0x0:
            self._hopLimit = ipv6.hlim
        else: # if hlim is 1, 2 or 3, there are nothing to do!
            pass
        
        # 4. Context (which context to use...)
        if self.cid == 0x0:
            pass
        else:
            #TODO: Context Unimplemented yet in my class
            self.__contextIdentifierExtension = 0
        
        # 5. Compress Source Addr
        self.compressSourceAddr(ipv6)
        self.compressDestinyAddr(ipv6)
        
        return Packet.do_build(self)
    
    def do_build_payload(self):
        ipv6 = self.payload
        
        if self.header_compression & 240 == 240: #TODO: UDP header IMPROVE
            return str(self.payload)[40+16:]
        else:
            return str(self.payload)[40:]
    
    def _getTrafficClassAndFlowLabel(self):
        """Page 6, draft feb 2011 """
        if self.tf == 0x0:
            return (self.tc_ecn << 6) + self.tc_dscp, self.flowlabel
        elif self.tf == 0x1:
            return (self.tc_ecn << 6), self.flowlabel
        elif self.tf == 0x2:
            return (self.tc_ecn << 6) + self.tc_dscp, 0
        else:
            return 0, 0

class SixLoWPAN(Packet):
    name = "SixLoWPAN(Packet)"

    def guess_payload_class(self, payload):
        """Depending on the payload content, the frame type we should interpretate"""
        if ord(payload[0]) >> 3 == 0x18:
            return LoWPANFragmentationFirst
        elif ord(payload[0]) >> 3 == 0x1C:
            return LoWPANFragmentationSubsequent
        elif ord(payload[0]) >> 6 == 0x02:
            return LoWPANMesh
        elif ord(payload[0]) >> 6 == 0x01:
            return LoWPAN_IPHC
        else:
            return payload

#fragmentate IPv6 or any other packet
MAX_SIZE = 96
def fragmentate(packet, datagram_tag):
    """Split a packet into different links to transmit as 6lowpan packets.
    """
    str_packet = str(packet)

    if len(str_packet) <= MAX_SIZE:
        return [packet]
    
    def chunks(l, n):
        return [l[i:i+n] for i in range(0, len(l), n)]

    new_packet = chunks(str_packet, MAX_SIZE)

    new_packet[0] = LoWPANFragmentationFirst(datagramTag = datagram_tag, datagramSize=len(str_packet))/new_packet[0]
    i=1
    while i<len(new_packet):
        new_packet[i] = LoWPANFragmentationSubsequent(datagramTag = datagram_tag, datagramSize=len(str_packet), datagramOffset=MAX_SIZE/8*i)/new_packet[i]
        i+=1

    return new_packet

#def defragmentate(packet_list):
#    payload = ""
#    for p in packet_list:
#        if type(p.payload) == LoWPANFragmentationFirst:
#            #print type(p.payload.payload)
#            payload = str(SixLoWPAN(p.payload.payload))
#        elif type(p.payload) == LoWPANFragmentationSubsequent:
#            print str(p.payload)
#            payload.payload += str(p.payload.payload)
#        else:
#            raise Exception
#    return SixLoWPAN(payload)
    


bind_layers( SixLoWPAN,         LoWPANFragmentationFirst,           )
bind_layers( SixLoWPAN,         LoWPANFragmentationSubsequent,      )
bind_layers( SixLoWPAN,         LoWPANMesh,                         )
bind_layers( SixLoWPAN,         LoWPAN_IPHC,                        )
bind_layers( LoWPANMesh,        LoWPANFragmentationFirst,           )
bind_layers( LoWPANMesh,        LoWPANFragmentationSubsequent,      )
#TODO: I have several doubts about the Broadcast LoWPAN
#bind_layers( LoWPANBroadcast,   LoWPANHC1CompressedIPv6,            )
#bind_layers( SixLoWPAN,         LoWPANBroadcast,                    )
#bind_layers( LoWPANMesh,        LoWPANBroadcast,                    )
#bind_layers( LoWPANBroadcast,   LoWPANFragmentationFirst,           )
#bind_layers( LoWPANBroadcast,   LoWPANFragmentationSubsequent,      )
bind_layers( LoWPANFragmentationFirst, LoWPAN_IPHC, )
bind_layers( LoWPANFragmentationSubsequent, LoWPAN_IPHC             )

#bind_layers( Dot15d4Data,         SixLoWPAN,             )


if __name__ == '__main__':
    #ip6_packet = LoWPANIPv6UncompressField(Reserved=0x1, Type=0x1) / \
    #    IPv6(src="AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:0000:1111")
    #ip6_packet.show()
    #ip6_packet.show2()
    #print str(ip6_packet)


    # some sample packet extracted
    icmp_string = "\x60\x00\x00\x00\x00\x08\x3a\x80\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x11\x22\xff\xfe\xfe\x33\x44\x55"
    

    lowpan_frag_first = "\xc3\x42\x00\x23\x78\xf6\x00\x06\x80\x00\x01\x00\x50\xc4\xf9\x00\x00\x02\x12\x77\x9b\x1a\x9a\x50\x18\x04\xc4\x12\xd5\x00\x00\x3c\x21\x44\x4f\x43\x54\x59\x50\x45\x20\x48\x54\x4d\x4c\x20\x50\x55\x42\x4c\x49\x43\x20\x22\x2d\x2f\x2f\x57\x33\x43\x2f\x2f\x44\x54\x44\x20\x48\x54\x4d\x4c\x20\x34\x2e\x30\x31\x20\x54\x72\x61\x6e\x73\x69\x74\x69\x6f\x6e\x61\x6c\x2f\x2f\x45\x4e\x22\x20\x22\x68\x74\x74\x70"

    lowpan_frag_first_packet = SixLoWPAN(lowpan_frag_first)
    #lowpan_frag_first_packet.show2()

    lowpan_frag_second = "\xe3\x42\x00\x23\x10\x3a\x2f\x2f\x77\x77\x77\x2e\x77\x33\x2e\x6f\x72\x67\x2f\x54\x52\x2f\x68\x74\x6d\x6c\x34\x2f\x6c\x6f\x6f\x73\x65\x2e\x64\x74\x64\x22\x3e\x0a\x3c\x68\x74\x6d\x6c\x3e\x3c\x68\x65\x61\x64\x3e\x3c\x74\x69\x74\x6c\x65\x3e\x57\x65\x6c\x63\x6f\x6d\x65\x20\x74\x6f\x20\x74\x68\x65\x20\x43\x6f\x6e\x74\x69\x6b\x69\x2d\x64\x65\x6d\x6f\x20\x73\x65\x72\x76\x65\x72\x21\x3c\x2f\x74\x69\x74\x6c\x65"

    #print
    #print

    #lowpan_frag_sec_packet = SixLoWPAN(lowpan_frag_second)
    #lowpan_frag_sec_packet.show2()

    #lowpan_iphc = "\x78\xf6\x00\x06\x80\x00\x01\x00\x50\xc4\xf9\x00\x00\x02\x12\x77\x9b\x1a\x9a\x50\x18\x04\xc4\x12\xd5\x00\x00\x3c\x21\x44\x4f\x43\x54\x59\x50\x45\x20\x48\x54\x4d\x4c\x20\x50\x55\x42\x4c\x49\x43\x20\x22\x2d\x2f\x2f\x57\x33\x43\x2f\x2f\x44\x54\x44\x20\x48\x54\x4d\x4c\x20\x34\x2e\x30\x31\x20\x54\x72\x61\x6e\x73\x69\x74\x69\x6f\x6e\x61\x6c\x2f\x2f\x45\x4e\x22\x20\x22\x68\x74\x74\x70"

    #lowpan_frag_iphc = LoWPAN_IPHC(lowpan_iphc)
    #lowpan_frag_iphc.show2()
    #p = LoWPAN_IPHC(tf=0x0, flowLabel=0x8, _nhField=0x3a, _hopLimit=64)/IPv6(dst="aaaa::11:22ff:fe33:4455", src="aaaa::1")/ICMPv6EchoRequest()
    #p.show2()
    #print hexdump(p)

    #q = LoWPAN_IPHC(tf=0x0)
    #print hexdump(q)

    #print
    #print

    #ip6 = IPv6(src="2002:db8::11:22ff:fe33:4455", dst="2002:db8::ff:fe00:1")
    #hexdump(ip6)

    # SAMPLE PACKETSS!!! IEEE 802.15.4 containing   
    
    ieee802_firstfrag = "\x41\xcc\xa3\xcd\xab\x16\x15\x14\xfe\xff\x13\x12\x02\x55\x44\x33\xfe\xff\x22\x11\x02\xc3\x42\x00\x23\x78\xf6\x00\x06\x80\x00\x01\x00\x50\xc4\xf9\x00\x00\x02\x12\x77\x9b\x1a\x9a\x50\x18\x04\xc4\x12\xd5\x00\x00\x3c\x21\x44\x4f\x43\x54\x59\x50\x45\x20\x48\x54\x4d\x4c\x20\x50\x55\x42\x4c\x49\x43\x20\x22\x2d\x2f\x2f\x57\x33\x43\x2f\x2f\x44\x54\x44\x20\x48\x54\x4d\x4c\x20\x34\x2e\x30\x31\x20\x54\x72\x61\x6e\x73\x69\x74\x69\x6f\x6e\x61\x6c\x2f\x2f\x45\x4e\x22\x20\x22\x68\x74\x74\x70\x39\xb5"

    #ieee = Dot15d4FCS(ieee802_firstfrag)
    #ieee.show2()
    #send(ieee)

    ieee802_secfrag = "\x41\xcc\x4d\xcd\xab\x55\x44\x33\xfe\xff\x22\x11\x02\x16\x15\x14\xfe\xff\x13\x12\x02\xe2\x39\x00\x17\x10\x69\x76\x65\x0d\x0a\x52\x65\x66\x65\x72\x65\x72\x3a\x20\x68\x74\x74\x70\x3a\x2f\x2f\x5b\x61\x61\x61\x61\x3a\x3a\x31\x31\x3a\x32\x32\x66\x66\x3a\x66\x65\x33\x33\x3a\x34\x34\x35\x35\x5d\x2f\x73\x65\x6e\x73\x6f\x72\x2e\x73\x68\x74\x6d\x6c\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x58\x31\x31\x3b\x20\x55\x3b\x20\x4c\x69\x66\xac"

    #ieee = Dot15d4FCS(ieee802_secfrag)
    #ieee.show2()

    ieee802_iphc = "\x41\xcc\xb5\xcd\xab\x16\x15\x14\xfe\xff\x13\x12\x02\x55\x44\x33\xfe\xff\x22\x11\x02\x78\xf6\x00\x06\x80\x00\x01\x00\x50\xc4\xfa\x00\x00\x01\xf7\x89\xf3\x02\x5f\x50\x18\x04\xc4\x48\x28\x00\x00\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x74\x79\x70\x65\x3a\x20\x74\x65\x78\x74\x2f\x63\x73\x73\x0d\x0a\x0d\x0a\xc1\x16"

    #ieee = Dot15d4FCS(ieee802_iphc)
    #ieee.show2()

    #hexdump(ieee)

    #print
    #print
    #p = AuxiliarySecurityHeaderIEEE802_15_4("\x04\x05\x00\x00\x00")
    #p.show2()

    #print
    #print

    #p = AuxiliarySecurityHeaderIEEE802_15_4("\x18\x05\x00\x00\x00\xff\xee\xdd\xcc\xbb\xaa\x00\x99\x88\x77")
    #p.show2()

    # TEST UDP HEADER COMPRESSION ##############################################
    udp_header_compression = "\xc2\x9c\x00\x2a\x7e\xf7\x00\xf0\x22\x3d\x16\x2e\x8e\x60\x10\x03\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x48\x65\x6c\x6c\x6f\x20\x31\x20\x66\x72\x6f\x6d\x20\x74\x68\x65\x20\x63\x6c\x69\x65\x6e\x74\x2e\x2d\x2e\x2d\x2e\x2d\x20\x30\x20\x33\x34\x35\x36\x37\x38\x39\x20\x31\x20\x33\x34\x35\x36\x37\x38\x39\x20\x32\x20\x33\x34\x35\x36\x37\x38\x39\x20\x33\x20\x33\x34\x35\x36\x37\x38\x39\x20\x34\x20\x33\x34\x35\x36"
    #TODO: fix
    #p = SixLoWPAN(udp_header_compression)
    #p.show2()
    #assert p.header_compression == 240
    #assert p.udpSourcePort == 8765
    #assert p.udpDestinyPort == 5678
    #assert p.udpChecksum == 0x8e60
    
    # udp 2
    udp = "\xe2\x9c\x00\x2a\x4d\x37\x38\x39\x20\x52\x20\x33\x34\x35\x36\x37\x38\x39\x20\x53\x20\x33\x34\x35\x36\x37\x38\x39\x20\x54\x20\x33\x34\x35\x36\x37\x38\x39\x20\x55\x20\x33\x34\x35\x36\x37\x38\x39\x20\x56\x20\x33\x34\x35\x36\x37\x38"
    
    p = SixLoWPAN(udp)
    assert p.datagramSize == 668
    assert p.datagramTag == 0x2a
    assert p.datagramOffset == 616/8 #TODO: should be multiplied by 8
    
    #udp 3
    udp = "\xe2\x9c\x00\x2a\x11\x37\x38\x39\x20\x35\x20\x33\x34\x35\x36\x37\x38\x39\x20\x36\x20\x33\x34\x35\x36\x37\x38\x39\x20\x37\x20\x33\x34\x35\x36\x37\x38\x39\x20\x38\x20\x33\x34\x35\x36\x37\x38\x39\x20\x39\x20\x33\x34\x35\x36\x37\x38\x39\x20\x61\x20\x33\x34\x35\x36\x37\x38\x39\x20\x62\x20\x33\x34\x35\x36\x37\x38\x39\x20\x63\x20\x33\x34\x35\x36\x37\x38\x39\x20\x64\x20\x33\x34\x35\x36\x37\x38\x39\x20\x65\x20\x10\x3e"
    
    p = SixLoWPAN(udp)
    assert p.datagramSize == 668
    assert p.datagramTag == 0x2a
    assert p.datagramOffset == 136/8
    
    #udp 4
    udp = "\xe2\x9c\x00\x2a\x1d\x33\x34\x35\x36\x37\x38\x39\x20\x66\x20\x33\x34\x35\x36\x37\x38\x39\x20\x67\x20\x33\x34\x35\x36\x37\x38\x39\x20\x68\x20\x33\x34\x35\x36\x37\x38\x39\x20\x69\x20\x33\x34\x35\x36\x37\x38\x39\x20\x6a\x20\x33\x34\x35\x36\x37\x38\x39\x20\x6b\x20\x33\x34\x35\x36\x37\x38\x39\x20\x6c\x20\x33\x34\x35\x36\x37\x38\x39\x20\x6d\x20\x33\x34\x35\x36\x37\x38\x39\x20\x6e\x20\x33\x34\x35\x36\x37\x38"
    
    p = SixLoWPAN(udp)
    assert p.datagramSize == 668
    assert p.datagramTag == 0x2a
    assert p.datagramOffset == 232/8
    #p.show2()
    #print str(p.payload.payload).encode('hex')
    
    #udp 5
    udp = "\xe2\x9c\x00\x2a\x29\x39\x20\x6f\x20\x33\x34\x35\x36\x37\x38\x39\x20\x70\x20\x33\x34\x35\x36\x37\x38\x39\x20\x71\x20\x33\x34\x35\x36\x37\x38\x39\x20\x72\x20\x33\x34\x35\x36\x37\x38\x39\x20\x73\x20\x33\x34\x35\x36\x37\x38\x39\x20\x74\x20\x33\x34\x35\x36\x37\x38\x39\x20\x75\x20\x33\x34\x35\x36\x37\x38\x39\x20\x76\x20\x33\x34\x35\x36\x37\x38\x39\x20\x77\x20\x33\x34\x35\x36\x37\x38\x39\x20\x78\x20\x33\x34"
    
    p = SixLoWPAN(udp)
    assert p.datagramSize == 668
    assert p.datagramTag == 0x2a
    assert p.datagramOffset == 328/8
    
    #udp 6
    udp = "\xe2\x9c\x00\x2a\x35\x35\x36\x37\x38\x39\x20\x79\x20\x33\x34\x35\x36\x37\x38\x39\x20\x7a\x20\x33\x34\x35\x36\x37\x38\x39\x20\x41\x20\x33\x34\x35\x36\x37\x38\x39\x20\x42\x20\x33\x34\x35\x36\x37\x38\x39\x20\x43\x20\x33\x34\x35\x36\x37\x38\x39\x20\x44\x20\x33\x34\x35\x36\x37\x38\x39\x20\x45\x20\x33\x34\x35\x36\x37\x38\x39\x20\x46\x20\x33\x34\x35\x36\x37\x38\x39\x20\x47\x20\x33\x34\x35\x36\x37\x38\x39\x20"
    
    p = SixLoWPAN(udp)
    assert p.datagramSize == 668
    assert p.datagramTag == 0x2a
    assert p.datagramOffset == 424/8
    ############################################################################
    
    # RPL: unimplemented
    #p = SixLoWPAN("\x7b\x3b\x3a\x1a\x9b\x02\xae\x30\x21\x00\x00\xef\x05\x12\x00\x80\x20\x02\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x33\x44\x09\x04\x00\x00\x00\x00\x06\x04\x00\x01\xef\xff")
    #p.show2()
    
    ipv6p = "\x60\x00\x00\x00\x02\x11\x06\x80\x20\x02\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x01\x20\x02\x0d\xb8\x00\x00\x00\x00\x00\x11\x22\xff\xfe\x33\x44\x55"

    tcpp = "\xc4\xf9\x00\x50\x77\x9b\x18\x9d\x00\x00\x01\xa2\x50\x18\x13\x58\x08\x10\x00\x00"

    httpp = "\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x5b\x61\x61\x61\x61\x3a\x3a\x31\x31\x3a\x32\x32\x66\x66\x3a\x66\x65\x33\x33\x3a\x34\x34\x35\x35\x5d\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x6b\x65\x65\x70\x2d\x61\x6c\x69\x76\x65\x0d\x0a\x52\x65\x66\x65\x72\x65\x72\x3a\x20\x68\x74\x74\x70\x3a\x2f\x2f\x5b\x61\x61\x61\x61\x3a\x3a\x31\x31\x3a\x32\x32\x66\x66\x3a\x66\x65\x33\x33\x3a\x34\x34\x35\x35\x5d\x2f\x73\x65\x6e\x73\x6f\x72\x2e\x73\x68\x74\x6d\x6c\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x58\x31\x31\x3b\x20\x55\x3b\x20\x4c\x69\x6e\x75\x78\x20\x69\x36\x38\x36\x3b\x20\x65\x6e\x2d\x55\x53\x29\x20\x41\x70\x70\x6c\x65\x57\x65\x62\x4b\x69\x74\x2f\x35\x33\x34\x2e\x31\x36\x20\x28\x4b\x48\x54\x4d\x4c\x2c\x20\x6c\x69\x6b\x65\x20\x47\x65\x63\x6b\x6f\x29\x20\x55\x62\x75\x6e\x74\x75\x2f\x31\x30\x2e\x31\x30\x20\x43\x68\x72\x6f\x6d\x69\x75\x6d\x2f\x31\x30\x2e\x30\x2e\x36\x34\x38\x2e\x31\x33\x33\x20\x43\x68\x72\x6f\x6d\x65\x2f\x31\x30\x2e\x30\x2e\x36\x34\x38\x2e\x31\x33\x33\x20\x53\x61\x66\x61\x72\x69\x2f\x35\x33\x34\x2e\x31\x36\x0d\x0a\x41\x63\x63\x65\x70\x74\x3a\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x6d\x6c\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x68\x74\x6d\x6c\x2b\x78\x6d\x6c\x2c\x74\x65\x78\x74\x2f\x68\x74\x6d\x6c\x3b\x71\x3d\x30\x2e\x39\x2c\x74\x65\x78\x74\x2f\x70\x6c\x61\x69\x6e\x3b\x71\x3d\x30\x2e\x38\x2c\x69\x6d\x61\x67\x65\x2f\x70\x6e\x67\x2c\x2a\x2f\x2a\x3b\x71\x3d\x30\x2e\x35\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x67\x7a\x69\x70\x2c\x64\x65\x66\x6c\x61\x74\x65\x2c\x73\x64\x63\x68\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x4c\x61\x6e\x67\x75\x61\x67\x65\x3a\x20\x65\x6e\x2d\x55\x53\x2c\x65\x6e\x3b\x71\x3d\x30\x2e\x38\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x43\x68\x61\x72\x73\x65\x74\x3a\x20\x49\x53\x4f\x2d\x38\x38\x35\x39\x2d\x31\x2c\x75\x74\x66\x2d\x38\x3b\x71\x3d\x30\x2e\x37\x2c\x2a\x3b\x71\x3d\x30\x2e\x33\x0d\x0a\x0d\x0a"

    #ipv6_tcp_http = IPv6(ipv6p + tcpp + httpp)

    #print fragmentate(ipv6_tcp_http, 0x17)
    
    
    # test ping
    #print
    #print
    #print
    #p = LoWPAN_IPHC()/IPv6("6000000000000000aaaa000000000000001122fffe334455aaaa00000000000000000000000000018000c4cd00000000".decode('hex'))
    #print str(p).encode('hex')
    
    
    
    ############################################################################
    #TODO: RPL
    packet = Dot15d4FCS("\x41\xc8\xad\xcd\xab\xff\xff\x18\x18\x18\x00\x18\x74\x12\x00\x7a\x3b\x3a\x1a\x9b\x00\xd8\xc6\x00\x00\x97\xa2")
    #packet.show2()
    assert packet.sourceAddr == "fe80::212:7418:18:1818"
    assert packet.destinyAddr == "ff02::1a"
    
    packet = Dot15d4FCS("\x41\xc8\x83\xcd\xab\xff\xff\x01\x01\x01\x00\x01\x74\x12\x00\x7a\x3b\x3a\x1a\x9b\x01\x2b\xee\x00\x00\x01\x00\x10\x02\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x04\x0e\x00\x08\x0c\x0a\x03\x00\x01\x00\x00\x01\x00\xff\xff\xff\x08\x1e\x40\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\x8b")
    assert packet.sourceAddr == "fe80::212:7401:1:101"
    assert packet.destinyAddr == "ff02::1a"
    #packet.show2()
    
    packet = Dot15d4FCS("\x41\xc8\x14\xcd\xab\xff\xff\x05\x05\x05\x00\x05\x74\x12\x00\x7a\x3b\x3a\x1a\x9b\x01\x24\xe3\x00\x00\x04\x00\x10\x01\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x04\x0e\x00\x08\x0c\x0a\x03\x00\x01\x00\x00\x01\x00\xff\xff\xff\x08\x1e\x40\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa8\x7b")
    assert packet.sourceAddr == "fe80::212:7405:5:505"
    assert packet.dst == "ff02::1a"
    #packet.show2()
    
    #TODO: Mesh Header. DOESNT WORK! (In wireshark it reports, malformed packet)
    #packet = SixLoWPAN("\x83\x00\x0a\x00\xff\x0a\x11\x78\x04\x00\x28\x00\x00\x00\x80\x00")
    #packet.show2()
    
    #TODO: Neighbour Solicitation (1st packet *417 file)
    print "##########################################"
    packet = LoWPAN_IPHC("\x7b\x49\x3a\x02\x01\xff\x02\x02\x02\x87\x00\x02\x0b\x00\x00\x00\x00\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x12\x74\x02\x00\x02\x02\x02")
    #packet.show2()
    print packet._nhField, packet.tc_ecn, packet.tc_dscp, packet.__padd, packet.flowlabel
    assert packet._nhField == 0x3a
    assert packet.src == "::"
    assert packet.dst == "ff02::1:ff02:202"
    #packet.show2()
    
    #TODO: Neighbour Solicitation (2nd packet *417 file)
    packet = SixLoWPAN("\x7b\x49\x3a\x02\x01\xff\x01\x01\x01\x87\x00\x57\xe6\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x02\x12\x74\x01\x00\x01\x01\x01")
    assert packet._nhField == 0x3a
    assert packet.sourceAddr == "::"
    assert packet.destinyAddr == "ff02::1:ff01:101"
    
    #TODO: Neighbour Advertisement (6th packet in *417 file)
    #packet = SixLoWPAN("\x7b\x33\x3a\x88\x00\x3c\xb9\x60\x00\x00\x00\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x12\x74\x02\x00\x02\x02\x02\x02\x02\x00\x12\x74\x02\x00\x02\x02\x02\x00\x00\x00\x00\x00\x00")
    #packet.show2()
    #assert packet.sourceAddr == "fe80::212:7402:2:202"
    #assert packet.destinyAddr == "fe80::212:7401:1:101"
    
    #TODO: real life raven
    first_frag_get_request = "\xc2\x39\x00\x17\x78\xe7\x00\x06\x80\x00\x01\xc4\xf9\x00\x50\x77\x9b\x18\x9d\x00\x00\x01\xa2\x50\x18\x13\x58\x08\x10\x00\x00\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x5b\x61\x61\x61\x61\x3a\x3a\x31\x31\x3a\x32\x32\x66\x66\x3a\x66\x65\x33\x33\x3a\x34\x34\x35\x35\x5d\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x6b\x65\x65\x70\x2d\x61\x6c"
    packet = SixLoWPAN(first_frag_get_request)
    #packet.show2()
    assert packet.datagramSize == 569
    assert packet.datagramTag == 0x17
    
    get_request = []
    get_request.append(SixLoWPAN("\xc2\x39\x00\x17\x78\xe7\x00\x06\x80\x00\x01\xc4\xf9\x00\x50\x77\x9b\x18\x9d\x00\x00\x01\xa2\x50\x18\x13\x58\x08\x10\x00\x00\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x20\x5b\x61\x61\x61\x61\x3a\x3a\x31\x31\x3a\x32\x32\x66\x66\x3a\x66\x65\x33\x33\x3a\x34\x34\x35\x35\x5d\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x6b\x65\x65\x70\x2d\x61\x6c"))
    
    get_request.append(SixLoWPAN("\xe2\x39\x00\x17\x10\x69\x76\x65\x0d\x0a\x52\x65\x66\x65\x72\x65\x72\x3a\x20\x68\x74\x74\x70\x3a\x2f\x2f\x5b\x61\x61\x61\x61\x3a\x3a\x31\x31\x3a\x32\x32\x66\x66\x3a\x66\x65\x33\x33\x3a\x34\x34\x35\x35\x5d\x2f\x73\x65\x6e\x73\x6f\x72\x2e\x73\x68\x74\x6d\x6c\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x58\x31\x31\x3b\x20\x55\x3b\x20\x4c\x69"))
    get_request.append(SixLoWPAN("\xe2\x39\x00\x17\x1c\x6e\x75\x78\x20\x69\x36\x38\x36\x3b\x20\x65\x6e\x2d\x55\x53\x29\x20\x41\x70\x70\x6c\x65\x57\x65\x62\x4b\x69\x74\x2f\x35\x33\x34\x2e\x31\x36\x20\x28\x4b\x48\x54\x4d\x4c\x2c\x20\x6c\x69\x6b\x65\x20\x47\x65\x63\x6b\x6f\x29\x20\x55\x62\x75\x6e\x74\x75\x2f\x31\x30\x2e\x31\x30\x20\x43\x68\x72\x6f\x6d\x69\x75\x6d\x2f\x31\x30\x2e\x30\x2e\x36\x34\x38\x2e\x31\x33\x33\x20\x43\x68\x72\x6f\x6d"))
    get_request.append(SixLoWPAN("\xe2\x39\x00\x17\x28\x65\x2f\x31\x30\x2e\x30\x2e\x36\x34\x38\x2e\x31\x33\x33\x20\x53\x61\x66\x61\x72\x69\x2f\x35\x33\x34\x2e\x31\x36\x0d\x0a\x41\x63\x63\x65\x70\x74\x3a\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x6d\x6c\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x68\x74\x6d\x6c\x2b\x78\x6d\x6c\x2c\x74\x65\x78\x74\x2f\x68\x74\x6d\x6c\x3b\x71\x3d\x30\x2e\x39\x2c\x74\x65\x78\x74"))
    get_request.append(SixLoWPAN("\xe2\x39\x00\x17\x34\x2f\x70\x6c\x61\x69\x6e\x3b\x71\x3d\x30\x2e\x38\x2c\x69\x6d\x61\x67\x65\x2f\x70\x6e\x67\x2c\x2a\x2f\x2a\x3b\x71\x3d\x30\x2e\x35\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x67\x7a\x69\x70\x2c\x64\x65\x66\x6c\x61\x74\x65\x2c\x73\x64\x63\x68\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x4c\x61\x6e\x67\x75\x61\x67\x65\x3a\x20\x65\x6e\x2d\x55\x53\x2c\x65\x6e\x3b"))
    
    #TODO: finish this
    #packet = defragmentate(get_request)
    #packet.show2()
    
    # It requires the ETH message
    #lowpan_iphc_header = "\x78\xe7\x00\x06\x80\x00\x01"
    #packet = SixLoWPAN(lowpan_iphc_header)
    #assert packet.tf == 0x3
    #assert packet.nh == 0
    #assert packet.hlim == 0x0
    #assert packet.cid == True
    #assert packet.sac == True
    #assert packet.sam == 0x2
    #assert packet.m == 0x0
    #assert packet.dac == 0x1
    #assert packet.dam == 0x03
    #assert packet._nhField == 0x06
    #assert packet._hopLimit == 128
    #packet.show2()
    
    # It requires the ETH message
    lowpan_iphc_header = "\x78\xf6\x00\x06\x80\x00\x01"
    packet = SixLoWPAN(lowpan_iphc_header)
    assert packet.tf == 0x3
    assert packet.nh == 0
    assert packet.hlim == 0x0
    assert packet.cid == True
    assert packet.sac == True
    assert packet.sam == 0x3
    assert packet.m == 0x0
    assert packet.dac == 0x1
    assert packet.dam == 0x02
    assert packet._nhField == 0x06
    assert packet._hopLimit == 128
    
    #lowpan_iphc_header = "\x78\xe7\x00\x06\x80\x00\x01"
    #packet = SixLoWPAN(lowpan_iphc_header)
    #assert packet.tf == 0x3
    #assert packet.nh == 0
    #assert packet.hlim == 0x0
    #assert packet.cid == True
    #assert packet.sac == True
    #assert packet.sam == 0x2
    #assert packet.m == 0x0
    #assert packet.dac == 0x1
    #assert packet.dam == 0x03
    #assert packet._nhField == 0x06
    #assert packet._hopLimit == 128
    #packet.show2()
    
    #ICMP: Neighbour Solicitation
    icmp = "\x7b\xf6\x00\x3a\x00\x01\x87\x00\xaa\x66\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x02\x02\x11\x22\xff\xfe\x33\x44\x55\x00\x00\x00\x00\x00\x00"
    packet = SixLoWPAN(icmp)
    #packet.show2()
    assert packet.tf == 0x3
    assert packet.nh == 0
    assert packet.hlim == 0x3
    assert packet.cid == True
    assert packet.sac == True
    assert packet.sam == 0x3
    assert packet.m == False
    assert packet.dac == True
    assert packet.dam == 0x2
    assert packet._nhField == 0x3a
    
    #extracted from test_raven file (2nd packet)
    #icmp = "\x7b\x3b\x3a\x01\x86\x00\xd3\xfd\x80\x00\x00\xc8\x00\x05\x7e\x40\x00\x00\x00\x00\x03\x04\x40\xc0\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x01\x00\x00\x00\x00\x05\x00\x01\x02\x02\x12\x13\xff\xfe\x14\x15\x16\x7b\x66\x6f\x6e\x74\x2d"
    #packet = LoWPAN_IPHC(icmp)
    #packet.show2()
    
    #the same message with ethernet header
    eth = "\x41\xc8\x49\xcd\xab\xff\xff\x16\x15\x14\xfe\xff\x13\x12\x02\x7b\x3b\x3a\x01\x86\x00\xd3\xfd\x80\x00\x00\xc8\x00\x05\x7e\x40\x00\x00\x00\x00\x03\x04\x40\xc0\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x01\x00\x00\x00\x00\x05\x00\x01\x02\x02\x12\x13\xff\xfe\x14\x15\x16\x7b\x66\x6f\x6e\x74\x2d\xa0\x90"
    packet = Dot15d4FCS(eth)
    #packet.show2()
    assert packet.destinyAddr == "ff02::1"
    assert packet.sourceAddr == "fe80::12:13ff:fe14:1516"
    
    
    #NOTE: this is not a real package, it's the first fragment from a udp packet
    # extracted from 6lowpan-test.pcap
    #udp = "\x7e\xf7\x00\xf0\x22\x3d\x16\x2e\x8e\x60\x10\x03\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x48\x65\x6c\x6c\x6f\x20\x31\x20\x66\x72\x6f\x6d\x20\x74\x68\x65\x20\x63\x6c\x69\x65\x6e\x74\x2e\x2d\x2e\x2d\x2e\x2d\x20\x30\x20\x33\x34\x35\x36\x37\x38\x39\x20\x31\x20\x33\x34\x35\x36\x37\x38\x39\x20\x32\x20\x33\x34\x35\x36\x37\x38\x39\x20\x33\x20\x33\x34\x35\x36\x37\x38\x39\x20\x34\x20\x33\x34\x35\x36"
    #packet = SixLoWPAN(udp)
    #assert packet.udpSourcePort == 8765
    #assert packet.udpDestinyPort == 5678
    #assert packet.udpChecksum == 0x8e60
    #assert packet.payload.payload.nh == 0x11 # the ipv6 header
    #assert packet.payload.payload.payload.sport == 8765 #udp decompressed header
    #assert packet.payload.payload.payload.dport == 5678 #udp decompressed header
    #assert packet.payload.payload.payload.chksum == 0x8e60 #udp decompressed header
    #packet.show2()
    
    # Check Traffic Class and Flow Label when TF=0
    packet = SixLoWPAN()/LoWPAN_IPHC(tf=0)/IPv6(tc = 12, fl=467)
    packet = SixLoWPAN(str(packet))
    assert (packet.tc_ecn << 6) + packet.tc_dscp == 12
    assert packet.flowlabel == 467
    # Check Traffic Class and Flow Label when TF=1
    packet = SixLoWPAN()/LoWPAN_IPHC(tf=1)/IPv6(tc = 12, fl=467)
    packet = SixLoWPAN(str(packet))
    assert packet.tc_ecn == 0 and packet.flowlabel == 467
    # Check Traffic Class and Flow Label when TF=2
    packet = SixLoWPAN()/LoWPAN_IPHC(tf=2)/IPv6(tc = 12, fl=467)
    packet = SixLoWPAN(str(packet))
    assert (packet.tc_ecn << 6) + packet.tc_dscp == 12 and packet.flowlabel == 0
    packet = SixLoWPAN()/LoWPAN_IPHC(tf=3)/IPv6(tc = 12, fl=467)
    packet = SixLoWPAN(str(packet))
    assert (packet.tc_ecn << 6) + packet.tc_dscp == 0 and packet.flowlabel == 0
    
    #TODO: Next Header Test
    
    #Checking the Hop Limit value in the IPv6 packet decompressed
    packet = SixLoWPAN()/LoWPAN_IPHC()/IPv6(tc = 12, fl=467, hlim=65)/ICMPv6EchoRequest()
    packet = SixLoWPAN(str(packet))
    assert packet.payload.payload.hlim == 65
    packet = SixLoWPAN()/LoWPAN_IPHC(hlim=1)/IPv6(tc = 12, fl=467, hlim=65)/ICMPv6EchoRequest()
    packet = SixLoWPAN(str(packet))
    assert packet.payload.payload.hlim == 1
    packet = SixLoWPAN()/LoWPAN_IPHC(hlim=2)/IPv6(tc = 12, fl=467, hlim=65)/ICMPv6EchoRequest()
    packet = SixLoWPAN(str(packet))
    assert packet.payload.payload.hlim == 64
    packet = SixLoWPAN()/LoWPAN_IPHC(hlim=3)/IPv6(tc = 12, fl=467, hlim=65)/ICMPv6EchoRequest()
    packet = SixLoWPAN(str(packet))
    assert packet.payload.payload.hlim == 255
    
    #TODO: Context Test
    
    # Check Source Address
    #packet = SixLoWPAN()/LoWPAN_IPHC(sam = 0, sac = 0)/IPv6(hlim=65, src="aaaa::1")/ICMPv6EchoRequest()
    #packet = SixLoWPAN(str(packet))
    #assert packet.payload.payload.src == "::1" # NO CONTEXT
    #packet = SixLoWPAN()/LoWPAN_IPHC(sam = 2, sac = 0)/IPv6(hlim=65, src="aaaa::1")/ICMPv6EchoRequest()
    #packet = SixLoWPAN(str(packet))
    #assert packet.payload.payload.src == "fe80::ff:fe00:1" # NO CONTEXT
    
    # Check Destiny Address
    
    
    # REAL PACKETS
    #packet = Dot15d4FCS("\x41\xcc\x38\xcd\xab\x55\x44\x33\xfe\xff\x22\x11\x02\x16\x15\x14\xfe\xff\x13\x12\x02\x7a\xe7\x00\x3a\x00\x01\x80\x00\xc4\xcd\x00\x00\x00\x00\x19\xb1")
    #packet.show2()
    ping_id = 0x7cc4
    ping_seq = 1
    ping_data = "\x77\xaf\x01\x4e\xc4\xb2\x03\x00\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
    
    # PING
    # echo request
    packet1 = SixLoWPAN()/LoWPAN_IPHC(tf=3, nh=0, hlim=2, cid=True)/IPv6(src="aaaa::11:22ff:fe33:4455", dst="aaaa::1")/ICMPv6EchoRequest(id=ping_id,seq=ping_seq, data=ping_data)
    #packet.show2()
    
    #SixLoWPAN(str(packet)).show2()
    
    # echo reply
    packet2 = SixLoWPAN()/LoWPAN_IPHC(tf=3, nh=0, hlim=2, cid=True)/IPv6(src="aaaa::11:22ff:fe33:4455", dst="aaaa::1")/ICMPv6EchoRequest(id=ping_id,seq=ping_seq, data=ping_data)
    
    print len(str(packet1)), len(str(packet2))
    
    # HAND SHAKE (http://www.workrobot.com/sansfire2009/SCAPY-packet-crafting-reference.html)
    #ip=IP(src="10.1.2.3", dst="10.2.3.4")
    #SYN=TCP(sport=1500, dport=80, flags="S", seq=100)
    #SYNACK=sr1(ip/SYN)

    #my_ack = SYNACK.seq + 1
    #ACK=TCP(sport=1050, dport=80, flags="A", seq=101, ack=my_ack)
    #send(ip/ACK)

    #payload="stuff"
    #PUSH=TCP(sport=1050, dport=80, flags="PA", seq=11, ack=my_ack)
    #send(ip/PUSH/payload)
    
    # ROUTER ADVERTISEMENT
    p = Dot15d4FCS("\x41\xc8\x58\xcd\xab\xff\xff\x16\x15\x14\xfe\xff\x13\x12\x02\x7b\x3b\x3a\x01\x86\x00\xf7\x2e\x80\x00\x00\xc8\x00\x05\x7e\x40\x00\x00\x00\x00\x03\x04\x40\xc0\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x01\x00\x00\x00\x00\x05\x00\x01\x02\x02\x12\x13\xff\xfe\x14\x15\x16\x6c\x6f\x63\x61\x6c\x00\x3e\x14")
    #Dot15d4FCS(str(p)).show2()
    
    p = IPv6("\x60\x00\x00\x00\x00\x48\x3a\xff\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x12\x13\xff\xfe\x14\x15\x16\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x86\x00\xf7\x2e\x80\x00\x00\xc8\x00\x05\x7e\x40\x00\x00\x00\x00\x03\x04\x40\xc0\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x01\x00\x00\x00\x00\x05\x00\x01\x02\x02\x12\x13\xff\xfe\x14\x15\x16\x6c\x6f\x63\x61\x6c\x00")
    p.show2()
