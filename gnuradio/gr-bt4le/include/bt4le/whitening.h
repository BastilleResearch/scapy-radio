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


#ifndef INCLUDED_BT4LE_WHITENING_H
#define INCLUDED_BT4LE_WHITENING_H

#include <bt4le/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace bt4le {

    /*!
     * \brief <+description of block+>
     * \ingroup bt4le
     *
     */
    class BT4LE_API whitening : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<whitening> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of bt4le::whitening.
       *
       * To avoid accidental use of raw pointers, bt4le::whitening's
       * constructor is in a private implementation
       * class. bt4le::whitening::make is the public interface for
       * creating new instances.
       */
      static sptr make(int chan_nbr=0);
    };

  } // namespace bt4le
} // namespace gr

#endif /* INCLUDED_BT4LE_WHITENING_H */

