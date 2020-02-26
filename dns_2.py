import sys
from ryu.lib.packet import packet as ryu_packet
from scapy.all import packet as scapy_packet
from ryu.lib.packet import *
from scapy.all import *
import chardet
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
import dns.resolver
import requests

# my_resolver = dns.resolver.Resolver()

# my_resolver.nameservers = ['8.8.8.8']
# answer = my_resolver.query('google.com', 'A')
# answer[0] = website


class DnsSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DnsSwitch, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        port = msg.match['in_port']
        pkt = ryu_packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4: # IF Ipv4
            if pkt_ipv4.proto == 17: #type int # IF UDP
               self.logger.info("--------------------")
               self.logger.info("Receive DNS Packet-in from %d", datapath.id)
               pkt_udp = pkt.get_protocol(udp.udp)
               data = msg.data
               self._handler_dns(datapath, pkt_ethernet, port, pkt_ipv4, pkt_udp, data)

    def _handler_dns(self,datapath,pkt_ethernet,port,pkt_ipv4,pkt_udp,data):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt_len = len(data)
        flag = data[42:44]
        b=chardet.detect(data[42:44])
        #print(b)
        if b['encoding'] == None:
            c=flag.encode("hex")
        else:
            flag.decode(b['encoding'])
            c=flag.encode("hex")
        d=int(c,16)
        domain = (data[55:pkt_len-5])
                # print(domain)
        doen = chardet.detect(domain)
        d_len = len(domain)
        for g in range(0,len(domain)-1):
            if ord(domain[g])<32 or ord(domain[g])>126:
                domain=domain[:g]+"."+domain[g+1:]
        ip_src = pkt_ipv4.dst
        ip_dst = pkt_ipv4.src
        sport = 53
        dport = pkt_udp.src_port
                domain_name = domain.split('.')[0] + '.' + domain.split('.')[1]+ '.' + domain.split('.')[2]
                print(domain_name)
                my_resolver = dns.resolver.Resolver()
                my_resolver.nameservers = ['8.8.8.8']
                answer = my_resolver.query(domain_name, 'A')
                ip = answer[0]
                print(ip)
        a = Ether(dst=pkt_ethernet.src,src=pkt_ethernet.dst)/IP(dst=ip_dst,src=ip_src)/UDP(sport=sport,dport=dport)/DNS(opcode=0,id=d,qr=1L,rd=1L,ra=1L,aa=0L,tc=0L,z=0L,ad=0L,cd=0L,rcode=0,qdcount=1,ancount=1,nscount=1,arcount=0,qd=DNSQR(qname=domain),
an=DNSRR(rrname=domain,ttl=60,rdata=ip),ns=DNSRR(rrname=domain,type=2,ttl=60,rdata="ns1."+domain),ar=None)
                try:
                    website = 'http://checksite.herokuapp.com/api/url=' + 'http://' + domain_name
                    print(website)
                    _status = requests.get(website)
                    print(_status)
                except Exception as e:
                    print(e)
                    pass
                else:
                    if _status.status_code == 200:
                        value = _status.json()
                        print(value)
                        if value['site']['id'] == 'bad':
                            a = Ether(dst=pkt_ethernet.src, src=pkt_ethernet.dst)/IP(dst=ip_dst, src=ip_src)/UDP(sport=sport,dport=dport)/DNS(opcode=0, id=d, qr=1L, rd=1L, ra=1L, aa=0L, tc=0L, z=0L, ad=0L, cd=0L, rcode=0, qdcount=1,ancount=1, nscount=1, arcount=0, qd=DNSQR(qname=domain),an=DNSRR(rrname=domain, ttl=60, rdata='10.10.110.1'),ns=DNSRR(rrname=domain, type=2, ttl=60, rdata='10.10.110.1'), ar=None)

                            print('Bad website found, ip spoofed to 10.10.110.1')
        data = str(a)
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=data)
        datapath.send_msg(out)
        self.logger.info("DNS Response sent to switch: %d",datapath.id)
                # "ns1."+domain

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch(eth_type=0x0800,ip_proto=17,udp_dst=53)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 65535, match, actions)
        actions = []
        self.add_flow(datapath, 65534, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

   
