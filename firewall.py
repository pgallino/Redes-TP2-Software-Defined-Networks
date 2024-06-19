from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr, IPAddr6
import os
import json

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp

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
        ip_versions = [4, 6] if 'IPv' not in rule else [rule['IPv']]

        for proto in protocols:
            for ip_version in ip_versions:
                modified_rule = rule.copy()
                modified_rule['protocol'] = proto
                modified_rule['IPv'] = ip_version
                flow_mod = self.create_flow_mod(modified_rule)
                event.connection.send(flow_mod)

    def create_flow_mod(self, rule):
        flow_mod = of.ofp_flow_mod()

        self.set_protocol(flow_mod, rule['protocol'])
        
        

        if 'dst_port' in rule:
            flow_mod.match.tp_dst = rule['dst_port']
        
        if 'src_ip' in rule:
            self.set_ip_address(flow_mod, rule)
        
        self.set_ip_type(flow_mod, rule['IPv'])

        return flow_mod

    def set_ip_address(self, flow_mod, rule):
        if rule['IPv'] == 6:
            flow_mod.match.nw_src = IPAddr6(rule['src_ip'])
        else:
            flow_mod.match.nw_src = IPAddr(rule['src_ip'])

    def set_ip_type(self, flow_mod, ip_version):
        if ip_version == 6:
            flow_mod.match.dl_type = ethernet.IPV6_TYPE
        elif ip_version == 4:
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
