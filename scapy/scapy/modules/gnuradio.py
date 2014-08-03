## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Airbus DS CyberSecurity
## Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
## This program is published under a GPLv2 license

"""
Gnuradio layers, sockets and send/receive functions.
"""

import socket, struct
import atexit
from scapy.config import conf
from scapy.data import MTU
from scapy.packet import *
from scapy.fields import *
from scapy.supersocket import SuperSocket
from scapy import sendrecv
from scapy import main
import scapy.layers.gnuradio


class GnuradioSocket(SuperSocket):
    desc = "read/write packets on a UDP Gnuradio socket"

    def __init__(self, peer="127.0.0.1"):
        SuperSocket.__init__(self, socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.outs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.tx_addr = (peer, 52001)
        self.rx_addr = (peer, 52002)
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.outs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        self.ins.bind(self.rx_addr)

    def recv(self, x=MTU):
        data, addr = self.ins.recvfrom(x)
        p = scapy.layers.gnuradio.GnuradioPacket(data)
        return p

    def send(self, pkt):
        if not pkt.haslayer(scapy.layers.gnuradio.GnuradioPacket):
            pkt = scapy.layers.gnuradio.GnuradioPacket()/pkt
        sx = str(pkt)
        if hasattr(pkt, "sent_time"):
            pkt.sent_time = time.time()
        self.outs.sendto(sx, self.tx_addr)


@conf.commands.register
def srradio(pkts, inter=0.1, *args, **kargs):
    """send and receive using a Gnuradio socket"""
    s = GnuradioSocket()
    a, b = sendrecv.sndrcv(s, pkts, inter=inter, *args, **kargs)
    s.close()
    return a, b


@conf.commands.register
def srradio1(pkts, *args, **kargs):
    """send and receive 1 packet using a Gnuradio socket"""
    a, b = srradio(pkts, *args, **kargs)
    if len(a) > 0:
        return a[0][1]


@conf.commands.register
def sniffradio(opened_socket=None, radio=None, *args, **kargs):
    if radio is not None:
        switch_radio_protocol(radio)
    s = opened_socket if opened_socket is not None else GnuradioSocket()
    rv = sendrecv.sniff(opened_socket=s, *args, **kargs)
    if opened_socket is None:
        s.close()
    return rv


def build_modulations_dict():
    conf.gr_modulations = {}
    grc_files = dict.fromkeys([x.rstrip(".grc") for x in os.listdir(conf.gr_mods_path) if x.endswith(".grc")], 0)
    topblocks = dict.fromkeys(
        [x for x in os.listdir(conf.gr_mods_path) if os.path.isdir(os.path.join(conf.gr_mods_path, x))], 0)
    for x in grc_files.keys():
        grc_files[x] = os.stat(os.path.join(conf.gr_mods_path, x + ".grc")).st_mtime
        try:
            os.mkdir(os.path.join(conf.gr_mods_path, x))
            topblocks[x] = 0
        except OSError:
            pass
    for x in topblocks.keys():
        topblocks[x] = os.stat(os.path.join(conf.gr_mods_path, x, 'top_block.py')).st_mtime if os.path.isfile(
            os.path.join(conf.gr_mods_path, x, 'top_block.py')) else 0
    for x in grc_files.keys():
        if grc_files[x] > topblocks[x]:
            outdir = "--directory=%s" % os.path.join(conf.gr_mods_path, x)
            input_grc = os.path.join(conf.gr_mods_path, x + ".grc")
            try:
                subprocess.check_call(["grcc", outdir, input_grc])
            except:
                pass
    for x in topblocks.keys():
        if os.path.isfile(os.path.join(conf.gr_mods_path, x, 'top_block.py')):
            conf.gr_modulations[x] = os.path.join(conf.gr_mods_path, x, 'top_block.py')


def sigint_ignore():
    import os
    os.setpgrp()


@conf.commands.register
def gnuradio_set_vars(host="localhost", port=8080, **kargs):
    try:
        import xmlrpclib
    except ImportError:
        print "xmlrpclib is missing to use this function."
    else:
        s = xmlrpclib.Server("http://%s:%d" % (host, port))
        for k, v in kargs.iteritems():
            try:
                getattr(s, "set_%s" % k)(v)
            except xmlrpclib.Fault:
                print "Unknown variable '%s'" % k
        s = None


@conf.commands.register
def gnuradio_get_vars(*args, **kargs):
    if "host" not in kargs:
        kargs["host"] = "127.0.0.1"
    if "port" not in kargs:
        kargs["port"] = 8080
    rv = {}
    try:
        import xmlrpclib
    except ImportError:
        print "xmlrpclib is missing to use this function."
    else:
        s = xmlrpclib.Server("http://%s:%d" % (kargs["host"], kargs["port"]))
        for v in args:
            try:
                res = getattr(s, "get_%s" % v)()
                rv[v] = res
            except xmlrpclib.Fault:
                print "Unknown variable '%s'" % v
        s = None
    if len(args) == 1:
        return rv[args[0]]
    return rv


@conf.commands.register
def gnuradio_stop_graph(host="localhost", port=8080):
    try:
        import xmlrpclib
    except ImportError:
        print "xmlrpclib is missing to use this function."
    else:
        s = xmlrpclib.Server("http://%s:%d" % (host, port))
        s.stop()
        s.wait()


@conf.commands.register
def gnuradio_start_graph(host="localhost", port=8080):
    try:
        import xmlrpclib
    except ImportError:
        print "xmlrpclib is missing to use this function."
    else:
        s = xmlrpclib.Server("http://%s:%d" % (host, port))
        try:
            s.start()
        except xmlrpclib.Fault as e:
            print "ERROR: %s" % e.faultString


@conf.commands.register
def switch_radio_protocol(layer, *args, **kargs):
    """Launches Gnuradio in background"""
    if conf.gr_modulations is None:
        build_modulations_dict()
    if not hasattr(conf, 'gr_process_io') or conf.gr_process_io is None:
        conf.gr_process_io = {'stdout': open('/tmp/gnuradio.log', 'w+'), 'stderr': open('/tmp/gnuradio-err.log', 'w+')}
    if layer not in conf.gr_modulations:
        print ""
        print "Available layers: %s" % ", ".join(conf.gr_modulations.keys())
        print ""
        raise AttributeError("Unknown radio layer %s" % layer)
    if conf.gr_process is not None:
        # An instance is already running
        conf.gr_process.kill()
        conf.gr_process = None
    try:
        conf.gr_process = subprocess.Popen(["env", "python2", conf.gr_modulations[layer]], preexec_fn=sigint_ignore,
                                           stdout=conf.gr_process_io['stdout'], stderr=conf.gr_process_io['stderr'])
    except OSError:
        return False
    return True


def gnuradio_exit(c):
    if hasattr(c, "gr_process") and hasattr(c.gr_process, "kill"):
        c.gr_process.kill()
    if hasattr(c, "gr_process_io") and c.gr_process_io is dict:
        for k in c.gr_process_io.keys():
            if c.gr_process_io[k] is file and not c.gr_process_io[k].closed:
                c.gr_process_io[k].close()
                c.gr_process_io[k] = None


atexit.register(gnuradio_exit, conf)
conf.L2socket = GnuradioSocket
conf.L3socket = GnuradioSocket
conf.L2listen = GnuradioSocket
for l in ["ZWave", "gnuradio", "dot15d4", "bluetooth4LE", "wmbus"]:
    main.load_layer(l)
conf.gr_modulations = {}
conf.gr_process = None
conf.gr_mods_path = os.path.join(os.path.expanduser("~"), ".scapy", "radio")
if not os.path.exists(conf.gr_mods_path):
    os.makedirs(conf.gr_mods_path)
build_modulations_dict()
