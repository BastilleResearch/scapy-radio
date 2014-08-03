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
#include "whitening_impl.h"
#include <gnuradio/block_detail.h>
#include <string.h>



namespace gr {
  namespace bt4le {

    whitening::sptr
    whitening::make(int chan_nbr)
    {
      return gnuradio::get_initial_sptr
        (new whitening_impl(chan_nbr));
    }

// bit swap 8 bits
 unsigned char whitening_impl::swap8bits(unsigned char a)
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

//************* packet whitening *************************
void whitening_impl::packet_whitening(char * data,int length){
for(unsigned char i=0;i<length;i++){
    unsigned char tmp ;
    tmp  = byte_whitening(data[i]);
    data[i] = tmp;
    }

}
//******************* whitening *************
unsigned char whitening_impl::byte_whitening(unsigned char data){

unsigned char tmp =data;
for(unsigned char iter=0; iter <8; iter++){
    if((whitening_reg & 0x80) != 0)
        {
            whitening_reg ^= 0x11;
            tmp ^= (1 << iter);
        }
        whitening_reg <<= 1;
    }
    return swap8bits(tmp); //FIXME
}

//****************** construtor **************************************
whitening_impl::whitening_impl(int chan_nbr)
  : gr::block("whitening",
          gr::io_signature::make(0, 0, 0),
          gr::io_signature::make(0, 0,0)),
         i_chan_nbr(chan_nbr)
{

        //init whitening
        init_whitening_reg = (swap8bits(i_chan_nbr)  | 0x02);
        //Init reg
        whitening_reg = init_whitening_reg; // Init of whitening

    message_port_register_out(pmt::mp("out"));

    message_port_register_in(pmt::mp("in"));
    set_msg_handler(pmt::mp("in"), boost::bind(&whitening_impl::make_frame, this, _1));

}

//****************** destuctor **************************************
    whitening_impl::~whitening_impl()
    {
    }
// ************************** main funct ****************************
void whitening_impl::make_frame (pmt::pmt_t msg) {

	if(pmt::is_eof_object(msg)) {
		message_port_pub(pmt::mp("out"), pmt::PMT_EOF);
		detail().get()->set_done(true);
		return;
	}

	assert(pmt::is_pair(msg));
	pmt::pmt_t blob = pmt::cdr(msg);

	size_t data_len = pmt::blob_length(blob);
	assert(data_len);
    assert(data_len > 5);
	assert(data_len < 256 - 7);


	std::memcpy(buf , pmt::blob_data(blob), data_len);
    whitening_reg = init_whitening_reg;
    packet_whitening(buf+7,data_len-7);

	pmt::pmt_t packet = pmt::make_blob(buf, data_len );

	message_port_pub(pmt::mp("out"), pmt::cons(pmt::PMT_NIL, packet));
}

  } /* namespace bt4le */
} /* namespace gr */

