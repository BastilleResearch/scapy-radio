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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "packet_sink_scapy_impl.h"
#include <cstdio>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdexcept>
#include <cstring>
#include <gnuradio/blocks/count_bits.h>
#include <iostream>

// very verbose output for almost each sample
#define VERBOSE 0
// less verbose output for higher level debugging
#define VERBOSE2 0

#define ZIGBEE 2

namespace gr {
  namespace zigbee {

    packet_sink_scapy::sptr
    packet_sink_scapy::make(int threshold)
    {
      return gnuradio::get_initial_sptr(new packet_sink_scapy_impl(threshold));
    }


void packet_sink_scapy_impl::enter_search()
{
	if (VERBOSE)
		fprintf(stderr, "@ enter_search\n");

	d_state = STATE_SYNC_SEARCH;
	d_shift_reg = 0;
	d_preamble_cnt = 0;
	d_chip_cnt = 0;
	d_packet_byte = 0;
}

void packet_sink_scapy_impl::enter_have_sync()
{
	if (VERBOSE)
		fprintf(stderr, "@ enter_have_sync\n");

	d_state = STATE_HAVE_SYNC;
	d_packetlen_cnt = 0;
	d_packet_byte = 0;
	d_packet_byte_index = 0;

	// Link Quality Information
	d_lqi = 0;
	d_lqi_sample_count = 0;
}

void packet_sink_scapy_impl::enter_have_header(int payload_len)
{
	if (VERBOSE)
		fprintf(stderr, "@ enter_have_header (payload_len = %d)\n", payload_len);

	d_state = STATE_HAVE_HEADER;
	d_packetlen  = payload_len;
	d_payload_cnt = 0;
	d_packet_byte = 0;
	d_packet_byte_index = 0;
}


unsigned char packet_sink_scapy_impl::decode_chips(unsigned int chips){
	int i;
	int best_match = 0xFF;
	int min_threshold = 33; // Matching to 32 chips, could never have a error of 33 chips

	for(i=0; i<16; i++) { //looking for the best matching
		// FIXME: we can store the last chip
		// ignore the first and last chip since it depends on the last chip.
		unsigned int threshold = gr::blocks::count_bits32((chips & 0x7FFFFFFE) ^ (CHIP_MAPPING[i] & 0x7FFFFFFE)); //nbr of bit != between the chip recept and chip table

		if (threshold < min_threshold) {
			best_match = i;
			min_threshold = threshold;
		}
	}

	if (min_threshold < d_threshold) {
		if (VERBOSE)
			fprintf(stderr, "Found sequence with %d errors at 0x%x\n", min_threshold, (chips & 0x7FFFFFFE) ^ (CHIP_MAPPING[best_match] & 0x7FFFFFFE)), fflush(stderr);
		// LQI: Average number of chips correct * MAX_LQI_SAMPLES
		//
		if (d_lqi_sample_count < MAX_LQI_SAMPLES) {
			d_lqi += 32 - min_threshold;
			d_lqi_sample_count++;
		}

		return (char)best_match & 0xF;
	}

	return 0xFF;
}

int packet_sink_scapy_impl::slice(float x) {    //cast un float => binaire
	return x > 0 ? 1 : 0;
}


    //**** * ***** Constructor
    packet_sink_scapy_impl::packet_sink_scapy_impl(int threshold)
      : gr::block("packet_sink_scapy",
		   gr::io_signature::make(1, 1, sizeof(float)),
		   gr::io_signature::make(0, 0, 0)),
    d_threshold(threshold)
    {
    d_sync_vector = 0xA7;

	// Link Quality Information
	d_lqi = 0;
	d_lqi_sample_count = 0;

	if ( VERBOSE )
		fprintf(stderr, "syncvec: %x, threshold: %d\n", d_sync_vector, d_threshold),fflush(stderr);
	enter_search();

	message_port_register_out(pmt::mp("out"));

    }

    //***************** Our virtual destructor. **************************************************
    packet_sink_scapy_impl::~packet_sink_scapy_impl()
    {
    }

    int
    packet_sink_scapy_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {

    const float *inbuf = (const float*)input_items[0];
    int ninput = ninput_items[0];
	int count=0;
	int i = 0;

	if (VERBOSE)
		fprintf(stderr,">>> Entering state machine\n"),fflush(stderr);

	while(count < ninput) {
		switch(d_state) {

		case STATE_SYNC_SEARCH:    // Look for sync vector
			if (VERBOSE)
				fprintf(stderr,"SYNC Search, ninput=%d syncvec=%x\n", ninput, d_sync_vector),fflush(stderr);

			while (count < ninput) {

				if(slice(inbuf[count++]))
					d_shift_reg = (d_shift_reg << 1) | 1;
				else
					d_shift_reg = d_shift_reg << 1;

				if(d_preamble_cnt > 0)  d_chip_cnt = d_chip_cnt+1;

                // The first if block syncronizes to chip sequences.
				if(d_preamble_cnt == 0){
					unsigned int threshold;
					threshold = gr::blocks::count_bits32((d_shift_reg & 0x7FFFFFFE) ^ (CHIP_MAPPING[0] & 0x7FFFFFFE));
					if(threshold < d_threshold) {
						//  fprintf(stderr, "Threshold %d d_preamble_cnt: %d\n", threshold, d_preamble_cnt);
						//if ((d_shift_reg&0xFFFFFE) == (CHIP_MAPPING[0]&0xFFFFFE)) {
						if (VERBOSE2)
							fprintf(stderr,"Found 0 in chip sequence\n"),fflush(stderr);
						// we found a 0 in the chip sequence
						d_preamble_cnt+=1;
						//fprintf(stderr, "Threshold %d d_preamble_cnt: %d\n", threshold, d_preamble_cnt);
					}
				} else {
					// we found the first 0, thus we only have to do the calculation every 32 chips
					if(d_chip_cnt == 32){
						d_chip_cnt = 0;

						if(d_packet_byte == 0) {
							if (gr::blocks::count_bits32((d_shift_reg & 0x7FFFFFFE) ^ (CHIP_MAPPING[0] & 0xFFFFFFFE)) <= d_threshold) {
								if (VERBOSE2)
									fprintf(stderr,"Found %d 0 in chip sequence\n", d_preamble_cnt),fflush(stderr);
								// we found an other 0 in the chip sequence
								d_packet_byte = 0;
								d_preamble_cnt ++;
							} else if (gr::blocks::count_bits32((d_shift_reg & 0x7FFFFFFE) ^ (CHIP_MAPPING[7] & 0xFFFFFFFE)) <= d_threshold) {
								if (VERBOSE2)
									fprintf(stderr,"Found first SFD\n"),fflush(stderr);
								d_packet_byte = 7 << 4;
							} else {
								// we are not in the synchronization header
								if (VERBOSE2)
									fprintf(stderr, "Wrong first byte of SFD. %u\n", d_shift_reg), fflush(stderr);
								enter_search();
								break;
							}

						} else {
							if (gr::blocks::count_bits32((d_shift_reg & 0x7FFFFFFE) ^ (CHIP_MAPPING[10] & 0xFFFFFFFE)) <= d_threshold) {
								d_packet_byte |= 0xA;
								if (VERBOSE2)
									fprintf(stderr,"Found sync, 0x%x\n", d_packet_byte),fflush(stderr);
								// found SDF
								// setup for header decode
								enter_have_sync();
								break;
							} else {
								if (VERBOSE)
									fprintf(stderr, "Wrong second byte of SFD. %u\n", d_shift_reg), fflush(stderr);
								enter_search();
								break;
							}
						}
					}
				}
			}
			break;

		case STATE_HAVE_SYNC:
			if (VERBOSE2)
				fprintf(stderr,"Header Search bitcnt=%d, header=0x%08x\n", d_headerbitlen_cnt, d_header),
				fflush(stderr);

			while (count < ninput) {		// Decode the bytes one after another.
				if(slice(inbuf[count++]))
					d_shift_reg = (d_shift_reg << 1) | 1;
				else
					d_shift_reg = d_shift_reg << 1;

				d_chip_cnt = d_chip_cnt+1;

				if(d_chip_cnt == 32){
					d_chip_cnt = 0;
					unsigned char c = decode_chips(d_shift_reg);
					if(c == 0xFF){
						// something is wrong. restart the search for a sync
						if(VERBOSE2)
							fprintf(stderr, "Found a not valid chip sequence! %u\n", d_shift_reg), fflush(stderr);

						enter_search();
						break;
					}

					if(d_packet_byte_index == 0){
						d_packet_byte = c;
					} else {
						// c is always < 15
						d_packet_byte |= c << 4;
					}
					d_packet_byte_index = d_packet_byte_index + 1;
					if(d_packet_byte_index%2 == 0){
						// we have a complete byte which represents the frame length.
						int frame_len = d_packet_byte;
						if(frame_len <= MAX_PKT_LEN){
							enter_have_header(frame_len);
						} else {
							enter_search();
						}
						break;
					}
				}
			}
			break;

		case STATE_HAVE_HEADER:
			if (VERBOSE2)
				fprintf(stderr,"Packet Build count=%d, ninput=%d, packet_len=%d\n", count, ninput, d_packetlen),fflush(stderr);

			while (count < ninput) {   // shift bits into bytes of packet one at a time
				if(slice(inbuf[count++]))
					d_shift_reg = (d_shift_reg << 1) | 1;
				else
					d_shift_reg = d_shift_reg << 1;

				d_chip_cnt = (d_chip_cnt+1)%32;

				if(d_chip_cnt == 0){
					unsigned char c = decode_chips(d_shift_reg);
					if(c == 0xff){
						// something is wrong. restart the search for a sync
						if(VERBOSE2)
							fprintf(stderr, "Found a not valid chip sequence! %u\n", d_shift_reg), fflush(stderr);

						enter_search();
						break;
					}
					// the first symbol represents the first part of the byte.
					if(d_packet_byte_index == 0){
						d_packet_byte = c;
					} else {
						// c is always < 15
						d_packet_byte |= c << 4;
					}
					//fprintf(stderr, "%d: 0x%x\n", d_packet_byte_index, c);
					d_packet_byte_index = d_packet_byte_index + 1;
					if(d_packet_byte_index%2 == 0){
						// we have a complete byte
						if (VERBOSE2)
							fprintf(stderr, "packetcnt: %d, payloadcnt: %d, payload 0x%x, d_packet_byte_index: %d\n", d_packetlen_cnt, d_payload_cnt, d_packet_byte, d_packet_byte_index), fflush(stderr);

						d_packet[d_packetlen_cnt++] = d_packet_byte;
						d_payload_cnt++;
						d_packet_byte_index = 0;

						if (d_payload_cnt >= d_packetlen){	// packet is filled, including CRC. might do check later in here
							unsigned int scaled_lqi = (d_lqi / MAX_LQI_SAMPLES) << 3;
							unsigned char lqi = (scaled_lqi >= 256? 255 : scaled_lqi);

							pmt::pmt_t meta = pmt::make_dict();
                            buf[0] = ZIGBEE;
                            buf[1] = 0x00; //Unused
                            buf[2] = 0x00; //Unused
                            buf[3] = 0x00; //Unused
                            buf[4] = 0x00; //Unused
                            buf[5] = 0x00; //Unused
                            buf[6] = 0x00; //Unused
                            buf[7] = 0x00; //Unused
							std::memcpy(buf+8, d_packet, d_packetlen_cnt);
							pmt::pmt_t payload = pmt::make_blob(buf, d_packetlen_cnt+8);

							message_port_pub(pmt::mp("out"), pmt::cons(meta, payload));

							if(VERBOSE2)
								fprintf(stderr, "Adding message of size %d to queue\n", d_packetlen_cnt);
							enter_search();
							break;
						}
					}
				}
			}
			break;

		default:
			assert(0);
			break;

		}
	}

	if(VERBOSE2)
		fprintf(stderr, "Samples Processed: %d\n", ninput_items[0]), fflush(stderr);

        consume(0, ninput_items[0]);

	return 0;
}


  } /* namespace zigbee */
} /* namespace gr */

