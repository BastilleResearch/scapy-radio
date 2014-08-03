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


#ifndef INCLUDED_SCAPY_RADIO_STRIP_GR_HEADER_H
#define INCLUDED_SCAPY_RADIO_STRIP_GR_HEADER_H

#include <scapy_radio/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace scapy_radio {

    /*!
     * \brief <+description of block+>
     * \ingroup scapy_radio
     *
     */
    class SCAPY_RADIO_API strip_gr_header : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<strip_gr_header> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of scapy_radio::strip_gr_header.
       *
       * To avoid accidental use of raw pointers, scapy_radio::strip_gr_header's
       * constructor is in a private implementation
       * class. scapy_radio::strip_gr_header::make is the public interface for
       * creating new instances.
       */
      static sptr make(int protocol_id);

      virtual int protocol_id() const = 0;
      virtual void set_protocol_id(int protocol_id) = 0;
    };

  } // namespace scapy_radio
} // namespace gr

#endif /* INCLUDED_SCAPY_RADIO_STRIP_GR_HEADER_H */

