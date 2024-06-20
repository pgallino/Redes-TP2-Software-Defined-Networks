from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr, IPAddr6
import os
import json

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4


log = core.getLogger()

class Controller(EventMixin):

    def __init__(self, config):
        self.listenTo(core.openflow)
        log.debug("Enabling Controller Module")
        self.config = config

    def _handle_ConnectionUp(self, event):
        if event.dpid == self.config['switch']:
            self.install_rules(event)

    def install_rules(self, event):
        for rule in self.config['rules']:
            self.apply_rule(event, rule)
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

    def apply_rule(self, event, rule):
        if 'mutual_block' in rule:
            self.apply_mutual_block(event, rule['mutual_block'])
        else:
            self.create_combinations_and_apply(event, rule)

    def create_combinations_and_apply(self, event, rule):
        protocols = ['TCP', 'UDP'] if 'protocol' not in rule else [rule['protocol']]

        for proto in protocols:
            modified_rule = rule.copy()
            modified_rule['protocol'] = proto
            flow_mod = self.create_flow_mod(modified_rule)
            event.connection.send(flow_mod)
            

    def create_flow_mod(self, rule):
        flow_mod = of.ofp_flow_mod()

        self.set_protocol(flow_mod, rule['protocol'])
        self.set_ip_type(flow_mod)

        if 'src_port' in rule:
            flow_mod.match.tp_src = rule['src_port']
        
        if 'dst_port' in rule:
            flow_mod.match.tp_dst = rule['dst_port']
        
        if 'src_ip' in rule:
            flow_mod.match.nw_src = IPAddr(rule['src_ip'])

        if 'dst_ip' in rule:
            flow_mod.match.nw_dst = IPAddr(rule['dst_ip'])
        
        return flow_mod

    def set_ip_type(self, flow_mod):
        flow_mod.match.dl_type = ethernet.IP_TYPE

    def set_protocol(self, flow_mod, protocol):
        if protocol == 'UDP':
            flow_mod.match.nw_proto = ipv4.UDP_PROTOCOL
        elif protocol == 'TCP':
            flow_mod.match.nw_proto = ipv4.TCP_PROTOCOL

    def apply_mutual_block(self, event, addresses):
        addr1, addr2 = addresses
        self.send_block_rule(event, addr1, addr2)
        self.send_block_rule(event, addr2, addr1)

    def send_block_rule(self, event, src, dst):
        flow_mod = of.ofp_flow_mod()
        flow_mod.match.dl_src = EthAddr(src)
        flow_mod.match.dl_dst = EthAddr(dst)
        event.connection.send(flow_mod)
    
    def _handle_PacketIn(self, event):
        packet = event.parsed
        if event.dpid == self.config['switch']:

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

def launch(config_file="config.json"):
    with open(config_file, 'r') as f:
        config = json.load(f)
    core.registerNew(Controller, config)
