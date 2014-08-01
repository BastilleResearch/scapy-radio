/* -*- c++ -*- */

#define BT4LE_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "bt4le_swig_doc.i"

%{
#include "bt4le/packet_sink.h"
#include "bt4le/preamble_prefixer.h"
#include "bt4le/whitening.h"
%}


%include "bt4le/packet_sink.h"
GR_SWIG_BLOCK_MAGIC2(bt4le, packet_sink);
%include "bt4le/preamble_prefixer.h"
GR_SWIG_BLOCK_MAGIC2(bt4le, preamble_prefixer);
%include "bt4le/whitening.h"
GR_SWIG_BLOCK_MAGIC2(bt4le, whitening);
