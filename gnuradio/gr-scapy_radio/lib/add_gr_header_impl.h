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

#ifndef INCLUDED_SCAPY_RADIO_ADD_GR_HEADER_IMPL_H
#define INCLUDED_SCAPY_RADIO_ADD_GR_HEADER_IMPL_H

#include <scapy_radio/add_gr_header.h>

namespace gr {
  namespace scapy_radio {

    class add_gr_header_impl : public add_gr_header
    {
     private:
        int _proto;

     public:
      add_gr_header_impl(int protocol_id);
      ~add_gr_header_impl();

      // Where all the action really happens
      void make_frame(pmt::pmt_t msg);

      int protocol_id() const { return _proto; };
      void set_protocol_id(int protocol_id) { _proto = protocol_id & 0xff; };
    };
  } // namespace scapy_radio
} // namespace gr

#endif /* INCLUDED_SCAPY_RADIO_ADD_GR_HEADER_IMPL_H */

