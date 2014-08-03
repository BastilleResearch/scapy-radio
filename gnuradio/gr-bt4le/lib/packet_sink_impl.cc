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
#include "packet_sink_impl.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <gnuradio/blocks/count_bits.h>
#include <iostream>

#define accept_bad_frame

//Debug print

//#define verbose_state
//#define debug_data_read

namespace gr {
  namespace bt4le {

packet_sink::sptr packet_sink::make(int i_chan_nbr)
    {
      return gnuradio::get_initial_sptr(new packet_sink_impl(i_chan_nbr));
    }

// bit swap 8 bits
unsigned char packet_sink_impl::swap8bits(unsigned char a)
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
//bit swap 32 bits
unsigned int packet_sink_impl::swap32bits(unsigned int a)
{
unsigned int v=0;
unsigned int iter=0;
unsigned int toto=0x80000000,tata=0x01;
for(;iter<32;iter++) if(a & (toto >> iter)) v |= (tata << iter);
return v;
}


// ************* Read header ************************************************
//>>>>>>>>>>>>>> FIXME : NEED TO CHECK IF LSB OR MSB in the core datasheet <<<<<<<<<<<<<<<<<<
unsigned int packet_sink_impl::read_header(unsigned int header_data)
{
    if(current_access_addr == ADV_ADDR) {
    //Advertising frame

        frame_struct.frame_type=0;
        frame_struct.length   =  (unsigned char)((header_data & 0x0000003F));
        frame_struct.PDU_type =  (unsigned char)((header_data & 0x00000f00) >> 8);
        frame_struct.TxAdd    =  (unsigned char)((header_data & 0x00002000) >> 13);
        frame_struct.RxAdd    =  (unsigned char)((header_data & 0x00001000) >> 12);
        std::cout << std::hex << int(frame_struct.PDU_type) << endl;
    }
    else{
    //Data frame
        frame_struct.frame_type=1;
        frame_struct.length = (unsigned char)((header_data & 0x0000003F));
    }
//FIXME :  length max ???!!!!!!
    if(frame_struct.length >= 250 || frame_struct.length <= 1){
        cout << "Length error" << endl;
        return 1;
    }

    frame_struct.frame[3] = (unsigned char)((current_access_addr & 0xFF000000) >> 24    );
    frame_struct.frame[2] = (unsigned char)((current_access_addr & 0x00FF0000) >> 16    );
    frame_struct.frame[1] = (unsigned char)((current_access_addr & 0x0000FF00) >> 8     );
    frame_struct.frame[0] = (unsigned char)(current_access_addr & 0x000000FF);

    frame_struct.frame[4] = (unsigned char)((header_data & 0x0000FF00) >> 8);
    frame_struct.frame[5] = (unsigned char)(header_data & 0x000000FF);

    return 0;
}

//************* Add an adress acces *****************************************
//return 1 if already in
unsigned int packet_sink_impl::add_access_addr(unsigned int i_access_addr,unsigned int CRC_init)
{
     std::map<unsigned int,unsigned int>::const_iterator it(access_addr.begin()), it_end(access_addr.end());
    for(;it != it_end;++it)    if(it->first == i_access_addr) return 1;
    access_addr[i_access_addr]= CRC_init;
    return 0;
}
//return 1 if CRC ok else 0
//************************************* compute CRC *******************
uint32_t packet_sink_impl::btLeCrc(void) {

    //FIXME : **************** Only works with Advertising frame *********************************************
    if(frame_struct.frame_type == 0 ){
    uint32_t state = 0x00AAAAAA;
    uint32_t len = frame_struct.length+6;
	uint32_t lfsr_mask = 0x5a6000; // 010110100110000000000000
	int i, j;

	for (i = 4; i < len; ++i) {
		uint8_t cur = frame_struct.frame[i];
		for (j = 0; j < 8; ++j) {
			int next_bit = (state ^ cur) & 1;
			cur >>= 1;
			state >>= 1;
			if (next_bit) {
				state |= 1 << 23;
				state ^= lfsr_mask;
			}
		}
	}

    if  ((((state & 0xff0000) >> 16) == frame_struct.frame[len+2]) && (((state & 0x00ff00) >> 8 )== frame_struct.frame[len+1]) && ((state & 0x0000ff) == frame_struct.frame[len+0]) )
        return 1;
    else
        return 0;
    }
    else
        return 1;

}


//************ Unwhitening ************************************************

unsigned char packet_sink_impl::unwhitening(unsigned char data){

unsigned char tmp = swap8bits(data);
for(unsigned char iter=0; iter <8; iter++){
    if((whitening_reg & 0x80) != 0)
        {
            whitening_reg ^= 0x11;
            tmp ^= (1 << iter);
        }
        whitening_reg <<= 1;
    }
    return tmp; //FIXME
}

//*********** Acces addr checking *******************************************
//Return 1 if match found
//return 0 if no match
//>>>>>>>>>>>>>>>> WITHOUT THREEHOLD ONLY FULL MATCH <<<<<<<<<<<<<<<<<<<<<<<<<<
unsigned int packet_sink_impl::acces_addr_check(void)
{
std::map<unsigned int,unsigned int>::const_iterator it(access_addr.begin()), it_end(access_addr.end());
for(;it != it_end;++it)
    {
        if(it->first == swap32bits(frame_shift_reg)) {
            current_access_addr= swap32bits(frame_shift_reg);
            return 1;
        }
    }
    return 0;

}

//*************   constructor ************************************
    packet_sink_impl::packet_sink_impl(int i_chan_nbr)
      : gr::block("packet_sink",
              gr::io_signature::make(1, 1, sizeof(char)),
              gr::io_signature::make(0, 0, 0))
    {
        //Set the channelstructure
        chan_nbr = i_chan_nbr;
        //Add advertising access addr
         add_access_addr(ADV_ADDR,0x555555);
        //SOME INIT
        state = PREAMBLE_SEARCH;
        data_shift = 0;
        //Load init value of LFSR :
        init_whitening_reg = (swap8bits(chan_nbr)  | 0x02);
        //Init
        whitening_reg = init_whitening_reg; // Init of whitening
        //default value of frame_shift_reg
        frame_shift_reg = 0x00000000;
        message_port_register_out(pmt::mp("out"));

    }


    //Our virtual destructor.
    packet_sink_impl::~packet_sink_impl(){
    }


int packet_sink_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
{
const unsigned char *inbuf = (const unsigned char*)input_items[0];
int ninput = ninput_items[0];
int count=0;

while(count < ninput){
    switch(state){
        case PREAMBLE_SEARCH :      //Looking for preamble if found go to next state
            while (count < ninput) {
                //update the shift register
                if(inbuf[count++])  frame_shift_reg = (frame_shift_reg << 1) | 1;
				else frame_shift_reg = frame_shift_reg << 1;
                //looking for a match in the acces addr table
                if(acces_addr_check() == 1){ //return 1 if found
                    whitening_reg = init_whitening_reg; // Init of whitening
                    state = HEADER_READING;
                    frame_shift = 40; //preamble + acces_addr 32 + 8bits
#ifdef verbose_state
        cout << "state = 2" << endl;
#endif
                        break;
                    }
            }
        break;

        case HEADER_READING :
            while(count < ninput){
                //update the shift register
                if(inbuf[count++])  frame_shift_reg = (frame_shift_reg << 1) | 1;
				else frame_shift_reg = frame_shift_reg << 1;
				frame_shift++;
				//wait for 56 shift to have the header in the first
                if(frame_shift == 56){
                    unsigned int unwhiten_head;
                    unwhiten_head = (unwhitening(((frame_shift_reg & 0x0000FF00) >> 8))) << 8;
                    unwhiten_head |= unwhitening((frame_shift_reg & 0x000000FF));
                    if(read_header(unwhiten_head) == 0){
                        //TODO : added a check on PDU_TYPE
                        if(frame_struct.PDU_type <= 6  && frame_struct.frame_type == 0){
                        data_shift=0;
                        state = READ_DATA;
#ifdef verbose_state
        cout << "state = 3" << endl;
#endif
                        break;
                        }
                        else{
                         frame_shift = 0;
                        //error back to search preamble
                        state = PREAMBLE_SEARCH;
                        break;
                        }
                    }
                    else
                    {
                        frame_shift = 0;
                        //error back to search preamble
                        state = PREAMBLE_SEARCH;
#ifdef verbose_state
        cout << "state = 0" << endl;
#endif
                        break;
                    }
                }
            }
        break;

        case READ_DATA :
             while(count < ninput){
                //update the shift register
                if(inbuf[count++])  frame_shift_reg = (frame_shift_reg << 1) | 1;
				else frame_shift_reg = frame_shift_reg << 1;
				frame_shift++;
                data_shift++;
                if( (data_shift%8) == 0){ //every 8bits we store a byte
                    frame_struct.frame[5+ (data_shift/8) ] = unwhitening(frame_shift_reg & 0x000000FF);
                    if((data_shift/8) == (frame_struct.length+4)){
                    if(frame_struct.frame_type == 0 ){
                        if(frame_struct.PDU_type == 5)
                                {
                                //FIXME : check endianness !!
                                //********************** Dissect con_requ *********************
                                //  buf[0,1,2,3]             = Acces_addr
                                //  buf[4,5]                 = Header
                                //  buf[6,7,8,9,10,11]       =   Addr
                                //  buf[12,13,14,15,16,17]   = Addr
                                if(frame_struct.length >= 24-8){
                                    uint32_t temp_addr=0,temp_crc=0;
                                    temp_addr = ((buf[18] << 24)   & 0xFF000000) + ((buf[19] << 16)   & 0x00FF0000) + ((buf[19] << 8)   & 0x0000FF00)
                                            + ((buf[20])   & 0x000000FF);
                                    temp_crc = ((buf[21] << 16)   & 0xFF0000) + ((buf[22] << 8)   & 0x00FF00) + ((buf[23])   & 0x0000FF);
                                    add_access_addr(temp_addr,temp_crc);
                                    std::cout << std::hex << "Add_acces_addr : " << int(temp_addr) << " CRC : "  << int(temp_crc) <<  std::endl;
                                    }
                                }
                            }
                       //check CRC
                      if ( btLeCrc() == 1){
                            pmt::pmt_t meta = pmt::make_dict();
                            buf[0] = BT4LE;
                            buf[1] = 0x00; //Unused
                            buf[2] = 0x00; //Unused
                            buf[3] = 0x00; //Unused
                            buf[4] = 0x00; //Unused
                            buf[5] = 0x00; //Unused
                            buf[6] = 0x00; //Unused
                            buf[7] = 0x00; //Unused

                            std::memcpy(buf+8, frame_struct.frame , (frame_struct.length + 3 + 6) );

                            pmt::pmt_t payload = pmt::make_blob(buf, (frame_struct.length + 3 + 6 + 8) ); //+8 for the preamble BT4LE
                            message_port_pub(pmt::mp("out"), pmt::cons(meta, payload));
                            data_shift=0;
                            frame_shift = 0;
                            state = PREAMBLE_SEARCH;
                        }
                        else{
                            frame_shift = 0;
                            data_shift=0;
                            state = PREAMBLE_SEARCH;
                            std::cout << "BAD CRC" << std::endl;
                        }
#ifdef verbose_state
    cout << "state = 0" << endl;
#endif
                        break;
                    }
                }
             }
        break;
    }

}

consume(0, ninput_items[0]);
// Tell runtime system how many output items we produced => 0 cause we use  PDU.
return 0;
}

}
}


