/* -*- c++ -*- */
/*
 * Copyright 2014 Airbus DS CyberSecurity.
 * Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_ZIGBEE_PACKET_SINK_SCAPY_IMPL_H
#define INCLUDED_ZIGBEE_PACKET_SINK_SCAPY_IMPL_H

#include <zigbee/packet_sink_scapy.h>

//FIXME : GLOBAL..............
static const unsigned int CHIP_MAPPING[] = {
					1618456172,
					1309113062,
					1826650030,
					1724778362,
					778887287,
					2061946375,
					2007919840,
					125494990,
					529027475,
					838370585,
					320833617,
					422705285,
					1368596360,
					85537272,
					139563807,
					2021988657
					};

static const int MAX_PKT_LEN    = 128 -  1; // remove header and CRC
static const int MAX_LQI_SAMPLES = 8; // Number of chip correlation samples to take

namespace gr {
  namespace zigbee {

    class packet_sink_scapy_impl : public packet_sink_scapy
    {
     private:
      // Nothing to declare in this block.
	enum {STATE_SYNC_SEARCH, STATE_HAVE_SYNC, STATE_HAVE_HEADER} d_state;

	unsigned int      d_sync_vector;           // 802.15.4 standard is 4x 0 bytes and 1x0xA7
	unsigned int      d_threshold;             // how many bits may be wrong in sync vector

	unsigned int      d_shift_reg;             // used to look for sync_vector
	int               d_preamble_cnt;          // count on where we are in preamble
	int               d_chip_cnt;              // counts the chips collected

	unsigned int      d_header;                // header bits
	int               d_headerbitlen_cnt;      // how many so far

	unsigned char     d_packet[MAX_PKT_LEN];   // assembled payload
	unsigned char     d_packet_byte;           // byte being assembled
	int               d_packet_byte_index;     // which bit of d_packet_byte we're working on
	int               d_packetlen;             // length of packet
	int               d_packetlen_cnt;         // how many so far
	int               d_payload_cnt;           // how many bytes in payload

	unsigned int      d_lqi;                   // Link Quality Information
	unsigned int      d_lqi_sample_count;

	// FIXME:
	char buf[256];

     public:
      packet_sink_scapy_impl(int threshold);
      ~packet_sink_scapy_impl();


      void enter_search(void);
      void enter_have_sync(void);
      void enter_have_header(int payload_len);
      unsigned char decode_chips(unsigned int chips);
      int slice(float x);

      // Where all the action really happens
      int general_work(int noutput_items,
		       gr_vector_int &ninput_items,
		       gr_vector_const_void_star &input_items,
		       gr_vector_void_star &output_items);
    };

  } // namespace zigbee
} // namespace gr

#endif /* INCLUDED_ZIGBEE_PACKET_SINK_SCAPY_IMPL_H */

