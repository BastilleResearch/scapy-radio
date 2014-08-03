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

#ifndef INCLUDED_BT4LE_PREAMBLE_PREFIXER_IMPL_H
#define INCLUDED_BT4LE_PREAMBLE_PREFIXER_IMPL_H

#include <bt4le/preamble_prefixer.h>

namespace gr {
  namespace bt4le {

    class preamble_prefixer_impl : public preamble_prefixer
    {
     private:
        //enought for a trame
        char preamble[256];

     public:
      preamble_prefixer_impl();
      ~preamble_prefixer_impl();

      // Where all the action really happens
      void make_frame (pmt::pmt_t msg);
      unsigned char swap8bits(unsigned char a);

    };

  } // namespace bt4le
} // namespace gr

#endif /* INCLUDED_BT4LE_PREAMBLE_PREFIXER_IMPL_H */

