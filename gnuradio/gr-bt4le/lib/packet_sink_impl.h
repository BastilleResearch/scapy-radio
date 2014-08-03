/* -*- c++ -*- */
/*
 * Copyright 2013 Airbus DS CyberSecurity.
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

#ifndef INCLUDED_BT4LE_PACKET_SINK_IMPL_H
#define INCLUDED_BT4LE_PACKET_SINK_IMPL_H

#include <bt4le/packet_sink.h>
#include <vector>

#define MAX_PDU_SIZE 47 //frame size not pdu
#define BT4LE   0x03

#define ADV_ADDR 0x8e89bed6

using namespace std;

namespace gr {
  namespace bt4le {

    class packet_sink_impl : public packet_sink
    {
     private:


	map<unsigned int,unsigned int>   access_addr;
	unsigned int current_access_addr;
    int chan_nbr;
    unsigned char frame_type;
    unsigned char whitening_reg;
    unsigned char init_whitening_reg;
    unsigned int frame_shift_reg;
	unsigned int frame_shift;
    unsigned int data_shift;
	enum {PREAMBLE_SEARCH, HEADER_READING, READ_DATA} state;

    struct s_frame_struct
        {
            unsigned char frame_type;
            unsigned int length;
            unsigned char PDU_type;
            unsigned char TxAdd;
            unsigned char RxAdd;
            unsigned char frame[MAX_PDU_SIZE+1];
        };
    struct s_frame_struct  frame_struct;
	// FIXME (fait de cette maniere sur Zigbee à voir pourquoi, probleme avec unsigned ou tableau trop petit IDK):
	char buf[256];


    public:

        uint32_t btLeCrc(void); //compute CRC
        unsigned int add_access_addr(unsigned int i_access_addr,unsigned CRC_init);    // Add an new acces addr
        unsigned char unwhitening(unsigned char data);      // Unwhitening the frame (((after acces addr))
        unsigned int acces_addr_check(void);                         // check match with acces table
        unsigned int swap32bits(unsigned int a);
        unsigned char swap8bits(unsigned char a);
        unsigned int read_header(unsigned int header_data);
        // Where all the action really happens
        int general_work(int noutput_items,
		       gr_vector_int &ninput_items,
		       gr_vector_const_void_star &input_items,
		       gr_vector_void_star &output_items);

        packet_sink_impl(int i_chan_nbr);
        ~packet_sink_impl();

    };

  } // namespace bt4le
} // namespace gr

#endif /* INCLUDED_BT4LE_PACKET_SINK_IMPL_H */

