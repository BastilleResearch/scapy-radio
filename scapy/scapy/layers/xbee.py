# -*- coding: utf-8 -*-
## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Jean-Michel Picod 2014
## This program is published under a GPLv2 license

from scapy.packet import *
from scapy.fields import *


class Xbee(Packet):
    description = "XBee"
    fields_desc = [
        ByteField("counter", None),
        ByteField("unk", None)
    ]
