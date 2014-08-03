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
#include <gnuradio/block_detail.h>
#include "strip_gr_header_impl.h"

namespace gr {
  namespace scapy_radio {

    strip_gr_header::sptr
    strip_gr_header::make(int protocol_id)
    {
      return gnuradio::get_initial_sptr
        (new strip_gr_header_impl(protocol_id));
    }

    /*
     * The private constructor
     */
    strip_gr_header_impl::strip_gr_header_impl(int protocol_id)
      : gr::block("strip_gr_header",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
        _proto(protocol_id & 0x0ff)
    {
        message_port_register_in(pmt::mp("in"));
        message_port_register_out(pmt::mp("out"));
        set_msg_handler(pmt::mp("in"), boost::bind(&strip_gr_header_impl::make_frame, this, _1));
    }

    /*
     * Our virtual destructor.
     */
    strip_gr_header_impl::~strip_gr_header_impl()
    {
    }

    void strip_gr_header_impl::make_frame(pmt::pmt_t msg)
    {
        if (pmt::is_eof_object(msg)) {
            message_port_pub(pmt::mp("out"), pmt::PMT_EOF);
            detail().get()->set_done(true);
            return;
        }
        assert(pmt::is_pair(msg));
        pmt::pmt_t blob = pmt::cdr(msg);
        unsigned char *data = (unsigned char *) pmt::blob_data(blob);

        size_t data_len = pmt::blob_length(blob);
        assert(data_len);
        if (data[0] == _proto && data_len > 8) {
            unsigned char *tmp = new unsigned char[data_len - 8];
            std::memcpy(tmp, data + 8, data_len - 8);
            pmt::pmt_t packet = pmt::make_blob(tmp, data_len - 8);
            message_port_pub(pmt::mp("out"), pmt::cons(pmt::PMT_NIL, packet));
            delete[] tmp;
        }
    }
  } /* namespace scapy_radio */
} /* namespace gr */

