# -*- coding: utf-8 -*-
## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Airbus DS CyberSecurity, 2014
## Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
## This program is published under a GPLv2 license

from scapy.packet import *
from scapy.fields import *


class Xbee(Packet):
    description = "XBee"
    fields_desc = [
        ByteField("counter", None),
        ByteField("unk", None)
    ]
