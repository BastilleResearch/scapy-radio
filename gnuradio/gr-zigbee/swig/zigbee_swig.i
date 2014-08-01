/* -*- c++ -*- */

#define ZIGBEE_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "zigbee_swig_doc.i"

%{
#include "zigbee/packet_sink_scapy.h"
#include "zigbee/preamble_prefixer_scapy.h"
%}


%include "zigbee/packet_sink_scapy.h"
GR_SWIG_BLOCK_MAGIC2(zigbee, packet_sink_scapy);
%include "zigbee/preamble_prefixer_scapy.h"
GR_SWIG_BLOCK_MAGIC2(zigbee, preamble_prefixer_scapy);
