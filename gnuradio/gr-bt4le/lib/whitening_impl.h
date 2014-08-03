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

#ifndef INCLUDED_BT4LE_WHITENING_IMPL_H
#define INCLUDED_BT4LE_WHITENING_IMPL_H

#include <bt4le/whitening.h>

namespace gr {
  namespace bt4le {

    class whitening_impl : public whitening
    {
     private:
        char buf[256];
        int i_chan_nbr;
        unsigned char whitening_reg;
        unsigned char init_whitening_reg;
     public:
      whitening_impl(int chan_nbr);
      ~whitening_impl();

      // Where all the action really happens

     unsigned char swap8bits(unsigned char a);
     unsigned char byte_whitening(unsigned char data);
     void packet_whitening(char * data,int length);
     void make_frame (pmt::pmt_t msg);
    };
  } // namespace bt4le
} // namespace gr

#endif /* INCLUDED_BT4LE_WHITENING_IMPL_H */

