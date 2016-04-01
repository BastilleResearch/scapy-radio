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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "preamble_prefixer_impl.h"
#include <string.h>
#include <gnuradio/block_detail.h>

using namespace gr::bt4le;
//**************************************************************************
//          Adapted from Zigbee
//**************************************************************************
namespace gr {
  namespace bt4le {


//***************** Swap8bits **********************************************
unsigned char preamble_prefixer_impl::swap8bits(unsigned char a)
{
	unsigned char v = 0;

	if(a & 0x80) v |= 0x01;
	if(a & 0x40) v |= 0x02;
	if(a & 0x20) v |= 0x04;
	if(a & 0x10) v |= 0x08;
	if(a & 0x08) v |= 0x10;
	if(a & 0x04) v |= 0x20;
	if(a & 0x02) v |= 0x40;
	if(a & 0x01) v |= 0x80;
	return v;

}

//************************* Constructor ************************************
preamble_prefixer_impl::preamble_prefixer_impl()
      : gr::block("preamble_prefixer",
        gr::io_signature::make(0, 0, 0),
        gr::io_signature::make(0, 0, 0))
{

    //init preamble
    preamble[0]=0x55;
    preamble[1]=0x55;
    preamble[2]=0x55;

    //Queue stuff
    message_port_register_out(pmt::mp("out"));
    message_port_register_in(pmt::mp("in"));
    set_msg_handler(pmt::mp("in"), boost::bind(&preamble_prefixer_impl::make_frame, this, _1));

}

//************************* Destructor *************************************
    preamble_prefixer_impl::~preamble_prefixer_impl()
    {
    }


// ******************** where everything happens ****************************

void preamble_prefixer_impl::make_frame (pmt::pmt_t msg) {

	if(pmt::is_eof_object(msg)) {
		message_port_pub(pmt::mp("out"), pmt::PMT_EOF);
		detail().get()->set_done(true);
		return;
	}
	assert(pmt::is_pair(msg));
	pmt::pmt_t blob = pmt::cdr(msg);

	size_t data_len = pmt::blob_length(blob);
	assert(data_len);
	assert(data_len < 256 - 1);


	std::memcpy(preamble + 3, ((const char*)pmt::blob_data(blob)) +8, data_len-8);

	//************************ swap Acces Addr field **********************************
	char tmp=0;
	tmp = preamble[3];

	preamble[3] = swap8bits(preamble[3]);
	preamble[4] = swap8bits(preamble[4]);
	preamble[5] = swap8bits(preamble[5]);
	preamble[6] = swap8bits(preamble[6]);

    preamble[data_len+3] = 0x00;
    preamble[data_len+4] = 0x00;
    preamble[data_len+5] = 0x00;
    preamble[data_len+6] = 0x00;
	pmt::pmt_t packet = pmt::make_blob(preamble, data_len + 3+4); //padding of 4 octets

	message_port_pub(pmt::mp("out"), pmt::cons(pmt::PMT_NIL, packet));
}

    preamble_prefixer::sptr
    preamble_prefixer::make()
    {
      return gnuradio::get_initial_sptr
        (new preamble_prefixer_impl());
    }

  } /* namespace bt4le */
} /* namespace gr */

