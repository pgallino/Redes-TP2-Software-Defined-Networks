from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from collections import namedtuple
import os

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp

log = core.getLogger()

class Controller(EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        log.debug("Enabling Controller Module")

    def _handle_ConnectionUp(self, event):
        if event.dpid == 1:
            #Rule 1
            rule1 = of.ofp_flow_mod()
            rule1.match.tp_dst = 80
            rule1.match.nw_proto = ipv4.TCP_PROTOCOL
            rule1.match.dl_type = ethernet.IP_TYPE
            rule1.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            event.connection.send(rule1)
            #Rule 2
            rule2 = of.ofp_flow_mod()
            rule2.match.tp_dst = 5001
            rule2.match.nw_proto = ipv4.UDP_PROTOCOL
            rule2.match.dl_type = ethernet.IP_TYPE
            rule2.match.nw_src = IPAddr("10.0.0.1")
            rule2.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            event.connection.send(rule2)
            #Rule 3 
            rule31 = of.ofp_flow_mod()
            rule31.match.dl_type = ethernet.IP_TYPE
            rule31.match.nw_src = IPAddr("10.0.0.2")
            rule31.match.nw_dst = IPAddr("10.0.0.3")
            #rule31.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            event.connection.send(rule31)
            rule32 = of.ofp_flow_mod()
            rule32.match.dl_type = ethernet.IP_TYPE
            rule32.match.nw_src = IPAddr("10.0.0.3")
            rule32.match.nw_dst = IPAddr("10.0.0.2")
            #rule32.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            event.connection.send(rule32)


            log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch():
    core.registerNew(Controller)