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
            #Rule 1
            rule1 = of.ofp_flow_mod()
            rule1.match.tp_dst = 80
            rule1.match.nw_proto = ipv4.UDP_PROTOCOL #Probablemente no hace falta
            rule1.match.dl_type = ethernet.IP_TYPE #Probablemente no hace falta
            #rule1.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            event.connection.send(rule1)
            #Rule 2
            rule2 = of.ofp_flow_mod()
            rule2.match.tp_dst = 5001
            rule2.match.nw_proto = ipv4.UDP_PROTOCOL
            rule2.match.dl_type = ethernet.IP_TYPE
            rule2.match.nw_src = IPAddr("10.0.0.1")
            #rule2.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            event.connection.send(rule2)
            #Rule 3 
            rule31 = of.ofp_flow_mod()
            rule31.match.dl_type = ethernet.IP_TYPE #Probablemente no hace falta
            rule31.match.dl_src = EthAddr("00:00:00:00:00:02")
            rule31.match.dl_dst = EthAddr("00:00:00:00:00:03")
            #rule31.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            event.connection.send(rule31)
            rule32 = of.ofp_flow_mod()
            rule32.match.dl_type = ethernet.IP_TYPE #Probablemente no hace falta
            rule32.match.dl_src = EthAddr("00:00:00:00:00:03")
            rule32.match.dl_dst = EthAddr("00:00:00:00:00:02")
            #rule32.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            event.connection.send(rule32)


            log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))
    
    def _handle_PacketIn(self, event):
        packet = event.parsed

        if packet.type == ethernet.IP_TYPE:
            ip_packet = packet.find('ipv4')
            if ip_packet:
                log.info("IPv4 PacketIn: src_ip=%s dst_ip=%s", ip_packet.srcip, ip_packet.dstip)

                tcp_packet = packet.find('tcp')
                if tcp_packet:
                    log.info("TCP PacketIn: src_port=%s dst_port=%s", tcp_packet.srcport, tcp_packet.dstport)

                udp_packet = packet.find('udp')    
                if udp_packet:
                    log.info("UDP PacketIn: src_port=%s dst_port=%s", udp_packet.srcport, udp_packet.dstport)

                icmp_packet = packet.find('icmp')
                if icmp_packet:
                    log.info("ICMP PacketIn: icmp_type=%s icmp_code=%s", icmp_packet.type, icmp_packet.code)

        msg = of.ofp_packet_out()
        event.connection.send(msg)

def launch():
    core.registerNew(Controller)