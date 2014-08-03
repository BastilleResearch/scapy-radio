/* -*- c++ -*- */
/*
 * Copyright 2013 Airbus DS CyberSecurity
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


#ifndef INCLUDED_BT4LE_PREAMBLE_PREFIXER_H
#define INCLUDED_BT4LE_PREAMBLE_PREFIXER_H

#include <bt4le/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace bt4le {

    class BT4LE_API preamble_prefixer : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<preamble_prefixer> sptr;
      static sptr make();
    };

  } // namespace bt4le
} // namespace gr

#endif /* INCLUDED_BT4LE_PREAMBLE_PREFIXER_H */

