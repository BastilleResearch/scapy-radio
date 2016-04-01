/* packet-scapy-radio.c
 * Routines for scapy-radio dissection
 * Copyright 2014, Jean-Michel PICOD
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <wireshark/config.h> /* needed for epan/gcc-4.x */
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/uat.h>

typedef struct _scapy_radio_encap_t {
    guint8 encap;
    char *payload_proto_name;
    dissector_handle_t payload_proto;
} scapy_radio_encap_t;

#define ENCAP0_STR  "Invalid frame"
/*static const value_string scapy_radio_payloads[256] = {
    {  0, ""},
    {  0, NULL}
};*/

static scapy_radio_encap_t* encaps = NULL;
static guint num_encaps = 0;
static uat_t* encaps_uat;
static dissector_table_t scapy_radio_table = NULL;

#define GNURADIO_HEADER_LENGTH  8

/* function prototypes */
void proto_reg_handoff_scapy(void);

static int proto_scapy = -1;

static int hf_scapy_pdu_type = -1;
static int hf_scapy_unused = -1;

static gint ett_scapy = -1;

/* subdissectors */
static dissector_handle_t data_handle = NULL;

/* dissect a packet */
static void
dissect_scapy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 subproto = 0;
    gint length = tvb_length_remaining(tvb, 0);
    tvbuff_t *new_tvb = NULL;
    scapy_radio_encap_t* encap = NULL;
    guint i;

	/* make entries in protocol column and info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "scapy_radio");

	subproto = tvb_get_guint8(tvb, 0);
	if (length > GNURADIO_HEADER_LENGTH) {
	    new_tvb = tvb_new_subset(tvb, GNURADIO_HEADER_LENGTH, -1, length);
	}

    for (i = 0; i < num_encaps; i++) {
        if (encaps[i].encap == subproto) {
            encap = &(encaps[i]);
            break;
        }
    }

    if (tree) {
        proto_item *ti = NULL;
        proto_item *junk = NULL;
        proto_tree *scapy_tree = NULL;
        dissector_handle_t next_handle = NULL;
        gint offset = 0;

        ti = proto_tree_add_item(tree, proto_scapy, tvb, 0, -1, ENC_NA);
        scapy_tree = proto_item_add_subtree(ti, ett_scapy);
        proto_tree_add_item(scapy_tree, hf_scapy_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(scapy_tree, hf_scapy_unused, tvb, offset, 7, ENC_NA);
        offset += 7;

        if (subproto == 0) {
            proto_item_set_text(ti, "scapy_radio (Invalid frame)");
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_NOTE, "scapy_radio (Invalid frame)");
            call_dissector(data_handle, new_tvb, pinfo, tree);
            return;
        }

        if (!encap) {
            char *msg = ep_strdup_printf("scapy_radio encapsulation not handled: proto=%d, "
                                         "check your Preferences->Protocols->scapy_radio",
                                         subproto);
            proto_item_set_text(ti, "%s", msg);
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "%s", msg);
            call_dissector(data_handle, new_tvb, pinfo, tree);
            return;
        }

        if (encap->payload_proto == NULL) {
            char *msg = ep_strdup_printf("scapy_radio encapsulation's protocol %s not found: "
                                         "proto=%d, check your Preferences->Protocols->scapy_radio",
                                         encap->payload_proto_name, subproto);
            proto_item_set_text(ti, "%s", msg);
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "%s", msg);
            call_dissector(data_handle, new_tvb, pinfo, tree);
            return;
        }

        call_dissector(encap->payload_proto, new_tvb, pinfo, tree);
    }
}

static void *scapy_copy_cb(void *dest, const void *orig, size_t len _U_)
{
    const scapy_radio_encap_t *o = (const scapy_radio_encap_t *) orig;
    scapy_radio_encap_t *d = (scapy_radio_encap_t *) dest;

    d->payload_proto_name = g_strdup(o->payload_proto_name);
}

static void scapy_free_cb(void *record)
{
    scapy_radio_encap_t *u = (scapy_radio_encap_t *) record;

    g_free(u->payload_proto_name);
}

UAT_DEC_CB_DEF(scapy_radio_encap, encap, scapy_radio_encap_t)
UAT_PROTO_DEF(scapy_radio_encap, payload_proto, payload_proto, payload_proto_name, scapy_radio_encap_t)

/* register the protocol with Wireshark */
void
proto_register_scapy(void)
{
    module_t *module;

    static uat_field_t scapy_flds[] = {
        UAT_FLD_DEC(scapy_radio_encap, encap, "Protocol ID", "scapy_radio payloads"),
        UAT_FLD_PROTO(scapy_radio_encap, payload_proto, "Payload protocol", "Protocol to be used for the payload of this DLT"),
        UAT_END_FIELDS
    };

    static hf_register_info hf[] = {
        {&hf_scapy_pdu_type,
            {"PDU Type", "scapy_radio.type",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
            }
        },
        {&hf_scapy_unused,
            {"Reserved for future use", "scapy_radio.unused",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
            }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_scapy
    };

	/* register the protocol name and description */
	proto_scapy = proto_register_protocol(
		"scapy_radio",	/* full name */
		"scapy_radio",	/* short name */
		"scapy_radio"	/* abbreviation (e.g. for filters) */
		);

    proto_register_field_array(proto_scapy, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module = prefs_register_protocol(proto_scapy, NULL);

    encaps_uat = uat_new("Scapy-radio PDU types table", sizeof (scapy_radio_encap_t),
                         "scapy_radio_payloads", TRUE, (void**) &encaps, &num_encaps, UAT_AFFECTS_DISSECTION,
                         "ChScapyPDUsSection", scapy_copy_cb, NULL, scapy_free_cb,
                         NULL, scapy_flds);
    prefs_register_uat_preference(module, "scapy_encaps_table", "Encapsulations table",
                                  "A table taht enumerates the various protocols to be used on top of scapy-radio",
                                  encaps_uat);

    scapy_radio_table = register_dissector_table("scapy_radio.type", "scapy_radio PDU dissecotrs", FT_UINT8, BASE_DEC);
	register_dissector("scapy_radio", dissect_scapy, proto_scapy);
}

void
proto_reg_handoff_scapy(void)
{
	static gboolean inited = FALSE;

	if (!inited) {
	    dissector_handle_t myself = find_dissector("scapy_radio");
	    data_handle = find_dissector("data");

		inited = TRUE;
	}
}
