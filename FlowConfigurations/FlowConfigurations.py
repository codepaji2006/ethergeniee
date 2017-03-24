#Distributed under GPLv2.0 license.
#Author: codepaji2006@github
#Repo: https://github.com/codepaji2006
#You may copy and distribute verbatim copies of the Program's source code as you
#receive it, in any medium, provided that you conspicuously and appropriately publish 
#on each copy an appropriate copyright notice and disclaimer of warranty; keep intact all
#the notices that refer to this License and to the absence of any warranty; and give any other recipients
#of the Program a copy of this License along with the Program.
#you must preserve the author and Repo notice when distributing or using this code.
#Disclaimer:Absolutely no warranty and your use is at your own risk

import xml.etree.ElementTree as ET
import struct
import socket
class FlowConfigurations:
    _root = ""
    _flows=[]
    def __init__(self, filename):
        tree = ET.parse(filename)
        config = tree.getroot()
        for flow in config:
            #print("Flow=", flow.tag)
            frame_list=[]
            for frame in flow:
                #print("     frame = ", frame.tag, frame.text)
                layer_dict=dict()
                for layers in frame:
                    ##print("         layers=", layers.tag, layers.text)
		    #TODO:
		    #if layers.tag in layer_dict:#multiple repeated layers take only first layer by OSI model
                    details_dict=dict()
                    for details in layers:
                        #print("                 details=", details.tag, details.text)
                        details_dict[details.tag]=details.text
                    layer_dict[layers.tag] = details_dict
                frame_list.append(layer_dict)
            self._flows.append(frame_list)

        self._root = config
        return

    def _ascii_2_binary_mac(self,ascii_mac):
        bin_mac=""
        a_hex_octets = ascii_mac.split(':')
        hex_octets = []
        for h in a_hex_octets:
            hex_octets.append(int(h, 16))
        bin_mac=hex_octets
        #bin_mac = struct.pack("BBBBBB",hex_octets[0],hex_octets[1],hex_octets[2],hex_octets[3],hex_octets[4],hex_octets[5])
        return bin_mac
    def _ascii_2_int_ip(self,ascii_ip):
        bin_ip=""
        a_hex_octets = ascii_ip.split('.')
        hex_octets=[]
        for h in a_hex_octets:
            hex_octets.append(int(h))
        bin_ip=0
        bin_ip|=hex_octets[0]<<24
        bin_ip |= hex_octets[1] << 16
        bin_ip |= hex_octets[2] << 8
        bin_ip |= hex_octets[3]
        #bin_ip=struct.pack("BBBB",hex_octets[0],hex_octets[1],hex_octets[2],hex_octets[3])
        return bin_ip
    def _htons(self,bin_proto):        
        n_proto = ((bin_proto & 0xf)<<8)|((bin_proto & 0xf0)>>8)
        return n_proto
        
    def _ascii_2_short_proto(self,ascii_proto):
        # type: (object) -> object
        # type: (object) -> object
        #print(ascii_proto.find('0x'))
        try:
            bin_proto = int(ascii_proto)
        except:
            bin_proto=int(ascii_proto,16)
        #print(bin_proto)
        return bin_proto
    def getEthernetProto(self,flow_index):
        return int(self._flows[flow_index][0]["Ethernet_header"]["proto"],16)
    def getVLANProto(self,flow_index):
        return int(self._flows[flow_index][0]["VLAN_header"]["h_vlan_encapsulated_proto"],16)
    def getIPProto(self,flow_index):
        return int(self._flows[flow_index][0]["IPv4_header"]["protocol"])
    def getVLANHeader(self,flow_index):
        dict_vlan=self._flows[flow_index][0]["VLAN_header"]
        vlanhdr=""
        h_vlan_TCI=self._ascii_2_short_proto(dict_vlan["h_vlan_TCI"])
        h_vlan_encapsulated_proto=self._ascii_2_short_proto(dict_vlan["h_vlan_encapsulated_proto"])
        vlanhdr=struct.pack("!HH",h_vlan_TCI,h_vlan_encapsulated_proto)
        return vlanhdr

    def getEthernetHeader(self,flow_index):
        dict_eth = self._flows[flow_index][0]["Ethernet_header"]
        h_dest=self._ascii_2_binary_mac(dict_eth["h_dest"])
        h_source=self._ascii_2_binary_mac(dict_eth["h_source"])
        proto = self._ascii_2_short_proto(dict_eth["proto"])
        ethhdr=struct.pack("!6B6BH",
                           h_dest[0],h_dest[1],h_dest[2],h_dest[3],h_dest[4],h_dest[5],
                           h_source[0],h_source[1],h_source[2],h_source[3],h_source[4],h_source[5],
                           proto)
        e=struct.unpack("!6B6BH",ethhdr)
        return ethhdr

    def getIPv4Header(self,flow_index):
        iphdr=bytearray(b"")
        dict_ip=self._flows[flow_index][0]["IPv4_header"]
        ihl=int(dict_ip["ihl"])
        version = int(dict_ip["version"])
        ihl_version=0
        ihl_version|=version<<4
        ihl_version|=ihl
        tos=int(dict_ip["tos"])
        tot_len=int(dict_ip["tot_len"])
        id=int(dict_ip["id"])
        frag_off=int(dict_ip["frag_off"])
        ttl=int(dict_ip["ttl"])
        protocol=int(dict_ip["protocol"])
        check=int(dict_ip["check"],16)
        saddr=self._ascii_2_int_ip(dict_ip["saddr"])
        daddr=self._ascii_2_int_ip(dict_ip["daddr"])
        iphdr=struct.pack("!BBHHHBBHII",ihl_version,tos,tot_len,id,frag_off,ttl,protocol,check,saddr,daddr)
        e=struct.unpack("!BBHHHBBHII",iphdr)
        return iphdr

    def getUDPHeader(self,flow_index):
        udphdr=bytearray(b"")
        dict_udp = self._flows[flow_index][0]["UDP_header"]
        source=self._ascii_2_short_proto(dict_udp["source"])
        dest=self._ascii_2_short_proto(dict_udp["dest"])
        lenp=self._ascii_2_short_proto(dict_udp["len"])
        check=self._ascii_2_short_proto(dict_udp["check"])
        udphdr = struct.pack("!HHHH",source,dest,lenp,check)
        return udphdr

    def getTCPHeader(self,flow_index):
        tcphdr=bytearray(b"")
        dict_tcp = self._flows[flow_index][0]["TCP_header"]
        source=self._ascii_2_short_proto(dict_tcp["source"])
        dest=self._ascii_2_short_proto(dict_tcp["dest"])
        seq=int(dict_tcp["seq"])
        ack_seq=int(dict_tcp["ack_seq"])
        res1=int(dict_tcp["res1"])
        doff=int(dict_tcp["doff"])
        fin=int(dict_tcp["fin"])
        syn=int(dict_tcp["syn"])
        rst=int(dict_tcp["rst"])
        psh=int(dict_tcp["psh"])
        ack=int(dict_tcp["ack"])
        urg=int(dict_tcp["urg"])
        window=int(dict_tcp["window"])
        check=int(dict_tcp["check"])
        urg_ptr=int(dict_tcp["urg_ptr"])
        flags=0#16 bit
        flags|=(doff<<12)
        flags|=(res1<<8)
        flags|=(urg<<5)
        flags|=(ack<<4)
        flags|=(psh<<3)
        flags|=(rst<<2)
        flags|=(syn<<1)
        flags|=(fin)
        tcphdr=struct.pack("!HHIIHHHH",source,dest,seq,ack_seq,flags,window,check,urg_ptr)
        return tcphdr

    def getICMPHeader(self,flow_index):
        icmphdr=""
        dict_icmp=self._flows[flow_index][0]["ICMP_header"]
        type=int(dict_icmp["type"])#1
        code=int(dict_icmp["code"])#1
        checksum=int(dict_icmp["checksum"],16)#2
        echo_id=int(dict_icmp["echo_id"])#2
        echo_sequence=int(dict_icmp["echo_sequence"])#2
        gateway=self._ascii_2_int_ip(dict_icmp["gateway"])#4
        frag_unused=int(dict_icmp["frag_unused"])#2
        frag_mtu=int(dict_icmp["frag_mtu"])#2
        if echo_id>0 and echo_sequence>0:#ignore frag and gateway
            un=0
            un|=(echo_id<<16)
            un|=echo_sequence
        elif gateway>0:
            un=gateway
        elif frag_mtu>0 and frag_unused>0:
            un=0
            un|=(frag_unused<<16)
            un|=frag_mtu
        icmphdr = struct.pack("!BBHI",type,code,checksum,un)
        return icmphdr

    def getCustomLayer(self,flow_index,layer_length):
        customlayer=""
	if "Custom_data" not in self._flows[flow_index][0]:
		return customlayer
        dict_custom = self._flows[flow_index][0]["Custom_data"]
        f = open(dict_custom["file"],"rb")
        customlayer=f.read(layer_length)
        f.close()
        return customlayer
    def getVlanProto(self,flow_index):
        dict_vlan = self._flows[flow_index][0]["VLAN_header"]
        vproto=self._ascii_2_short_proto(dict_vlan["h_vlan_encapsulated_proto"])
        return vproto
    def getFrame(self, flow_index, payload_bytes):
        ethhdr = self.getEthernetHeader(flow_index)
        vlanhdr=""
        layer3_hdr=""
        layer4_hdr=""
        is_vlan=False
        if self.getEthernetProto(flow_index) == 0x8100:
            vlanhdr = self.getVLANHeader(flow_index)
            is_vlan=True
        if self.getEthernetProto(flow_index) == 0x800:
                layer3_hdr = self.getIPv4Header(flow_index)
                if self.getIPProto(flow_index) == 17:
                    layer4_hdr = self.getUDPHeader(flow_index)
                elif self.getIPProto(flow_index) == 1:
                    layer4_hdr = self.getICMPHeader(flow_index)
                elif self.getIPProto(flow_index) == 6:
                    layer4_hdr = self.getTCPHeader(flow_index)
                else:
                    pass
	elif self.getEthernetProto(flow_index) == 0x8100 and self.getVlanProto(flow_index)==0x800:
                layer3_hdr = self.getIPv4Header(flow_index)
                if self.getIPProto(flow_index) == 17:
                    layer4_hdr = self.getUDPHeader(flow_index)
                elif self.getIPProto(flow_index) == 1:
                    layer4_hdr = self.getICMPHeader(flow_index)
                elif self.getIPProto(flow_index) == 6:
                    layer4_hdr = self.getTCPHeader(flow_index)
                else:
                    pass
        layer4_data = self.getCustomLayer(flow_index, payload_bytes)
        final_frame = bytearray()
        final_frame += ethhdr
        final_frame += vlanhdr
        final_frame += layer3_hdr
        final_frame += layer4_hdr
        final_frame += layer4_data
        return final_frame
