#!/usr/bin/python

from socket import AF_INET, AF_INET6
import os
import sys
if  os.name.find("nt")<0:
	from socket import inet_ntop
elif os.name.find("nt")>=0:
	from socket import inet_ntoa



if os.name.find("nt")<0:

    from ctypes import (
        Structure, Union, POINTER,
        pointer, get_errno, cast,
        c_ushort, c_byte, c_void_p, c_char_p, c_uint, c_int, c_uint16, c_uint32
    )
    import ctypes.util
    import ctypes
    import socket
    class RawSocket:
	    _sockfd=""
	    def __init__(self, interface):
		self._sockfd = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
		self._sockfd.bind((interface, socket.SOCK_RAW))
		return

	    def sendframe(self,frame,framelen):
		self._sockfd.send(frame)
		return

    class bsd_sockaddr(Structure):
        _fields_ = [
            ('sa_family', c_ushort),
            ('sa_data', c_byte * 14),]

    class bsd_sockaddr_in(Structure):
        _fields_ = [
            ('sin_family', c_ushort),
            ('sin_port', c_uint16),
            ('sin_addr', c_byte * 4)]

    class bsd_sockaddr_in6(Structure):
        _fields_ = [
            ('sin6_family', c_ushort),
            ('sin6_port', c_uint16),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr', c_byte * 16),
            ('sin6_scope_id', c_uint32)]

    class union_ifa_ifu(Union):
        _fields_ = [
            ('ifu_broadaddr', POINTER(bsd_sockaddr)),
            ('ifu_dstaddr', POINTER(bsd_sockaddr)),]

    class bsd_ifaddr(Structure):
        pass
    bsd_ifaddr._fields_ = [
        ('ifa_next', POINTER(bsd_ifaddr)),
        ('ifa_name', c_char_p),
        ('ifa_flags', c_uint),
        ('ifa_addr', POINTER(bsd_sockaddr)),
        ('ifa_netmask', POINTER(bsd_sockaddr)),
        ('ifa_ifu', union_ifa_ifu),
        ('ifa_data', c_void_p),]

    libc = ctypes.CDLL(ctypes.util.find_library('c'))

    def ifap_iter(ifap):
        ifa = ifap.contents
        while True:
            yield ifa
            if not ifa.ifa_next:
                break
            ifa = ifa.ifa_next.contents

    def get_family_and_address_for_dev(sa):
        family = sa.sa_family
        addr = None
        if family == AF_INET:
            sa = cast(pointer(sa), POINTER(bsd_sockaddr_in)).contents
            addr = inet_ntop(family, sa.sin_addr)
        elif family == AF_INET6:
            sa = cast(pointer(sa), POINTER(bsd_sockaddr_in6)).contents
            addr = inet_ntop(family, sa.sin6_addr)
        return family, addr

    class Ethdevice(object):
        def __init__(self, name):
            self.name = name
            self.index = libc.if_nametoindex(name)
            self.addresses = {}

        def __str__(self):
            return "%s [index=%d, IPv4=%s, IPv6=%s]" % (
                self.name, self.index,
                self.addresses.get(AF_INET),
                self.addresses.get(AF_INET6))

    def get_network_interfaces():
        ifap = POINTER(bsd_ifaddr)()
        result = libc.getifaddrs(pointer(ifap))
        if result != 0:
            raise OSError(get_errno())
        del result
        try:
            retval = {}
            for ifa in ifap_iter(ifap):
                name = ifa.ifa_name
                i = retval.get(name)
                if not i:
                    i = retval[name] = Ethdevice(name)
                family, addr = get_family_and_address_for_dev(ifa.ifa_addr.contents)
                if addr:
                    i.addresses[family] = addr
            return retval.values()
        finally:
            libc.freeifaddrs(ifap)
    def send_frame(out_dev,final_frame,frame_len):
        res=0
        s = RawSocket(out_dev)
        print("Flow index:%d packet length:%d bytes"%(0,frame_len))
        s.sendframe(final_frame,frame_len)
        return res
    
else:
    from ctypes import *
    import socket
    class bsd_sockaddr( Structure):
        _fields_ = [("sa_family",  c_ushort),
                    ("sa_data",  c_char * 14)]
      
    class bsd_sockaddr_in(Structure):
            _fields_ = [
                ('sin_family', c_ushort),
                ('sin_port', c_uint16),
                ('sin_addr', c_byte * 4)]

    class bsd_sockaddr_in6(Structure):
            _fields_ = [
                ('sin6_family', c_ushort),
                ('sin6_port', c_uint16),
                ('sin6_flowinfo', c_uint32),
                ('sin6_addr', c_byte * 16),
                ('sin6_scope_id', c_uint32)]

           
    class winpcap_addr( Structure):
        pass
      
    winpcap_addr._fields_ = [('next',  POINTER(winpcap_addr)),
                          ('addr',  POINTER(bsd_sockaddr)),
                          ('netmask',  POINTER(bsd_sockaddr)),
                          ('broadaddr',  POINTER(bsd_sockaddr)),
                          ('dstaddr',  POINTER(bsd_sockaddr))]
    class winpcap_if( Structure):
        pass
      
    winpcap_if._fields_ = [('next',  POINTER(winpcap_if)),
                        ('name',  c_char_p),
                        ('description',  c_char_p),
                        ('addresses',  POINTER(winpcap_addr)),
                        ('flags',  c_uint)]

    def winpcap_close(handle):
        winpcap_close = cdll.wpcap.pcap_close
        winpcap_close.restype = None
        winpcap_close.argtypes=[POINTER(c_void_p)]
        winpcap_close(handle)
        return
    def winpcap_sendpacket(handle,buff,bufflen):
        winpcap_sendpacket = cdll.wpcap.pcap_sendpacket
        winpcap_sendpacket.restype = c_int
        winpcap_sendpacket.argtype =[POINTER(c_void_p),
                                  POINTER(c_void_p),
                                  c_int]
      
        v_pkt_data = c_buffer(bufflen)
        v_pkt_data.value = str(buff)
        
        
        res = winpcap_sendpacket(handle,v_pkt_data,bufflen)
        return res
        


    def winpcap_freealldevs(alldevs):
        winpcap_freealldevs = cdll.wpcap.pcap_freealldevs
        winpcap_freealldevs.restype = None
        winpcap_freealldevs.argtypes = [ POINTER(winpcap_if)]
        winpcap_freealldevs(alldevs)
      
      
    def winpcap_open_live(device, snaplen, promisc, to_ms):
        winpcap_open_live = cdll.wpcap.pcap_open_live
        winpcap_open_live.restype =  POINTER( c_void_p)
        winpcap_open_live.argtypes = [c_char_p,
                                   c_int,
                                   c_int,
                                   c_int,
                                   c_char_p]
        errbuf =  c_buffer(256)
        dev = c_buffer(device)
        handle = winpcap_open_live(dev, snaplen, promisc, to_ms, errbuf)
        if not handle:
            print "Error opening device %s." % device
            return None
        return handle
    def winpcap_findalldevs():
        winpcap_findalldevs = cdll.wpcap.pcap_findalldevs
        winpcap_findalldevs.restype = c_int
        winpcap_findalldevs.argtypes = [POINTER(POINTER(winpcap_if)),
                                     c_char_p]
        errbuf = c_buffer(256)
        alldevs =POINTER(winpcap_if)()
        result = winpcap_findalldevs( byref(alldevs), errbuf)
        devices = []
        libcc = cdll.msvcrt
        if result == 0:
            device = alldevs.contents
            

            while(device):
                td=dict()
                
                pa=device.addresses.contents
                sa=pa.addr.contents
                ssa = cast(pointer(sa), POINTER(bsd_sockaddr_in)).contents
                
                ad = ''
                if sa.sa_family == socket.AF_INET:
                    family="AF_INET"
                elif sa.sa_family ==socket.AF_INET6:
                    family="AF_INET6"
                else:
                    family="unspecified"
                
                td['Interface']=device.name
                td['IPv6']=''
                
                str_to_print6="Interface:%s  Family:%s  Address:%s"%(device.name,
                               family,ad)
                               
                pa=device.addresses.contents.next.contents
                sa=pa.addr.contents
                ssa = cast(pointer(sa), POINTER(bsd_sockaddr_in)).contents
                
                ad = "%u.%u.%u.%u"%(ssa.sin_addr[0],
                                    ssa.sin_addr[1],
                                    ssa.sin_addr[2],
                                    ssa.sin_addr[3])
                if sa.sa_family == socket.AF_INET:
                    family="AF_INET"
                elif sa.sa_family ==socket.AF_INET6:
                    family="AF_INET6"
                else:
                    family="unspecified"

                str_to_print4="Interface:%s  Family:%s  Address:%s"%(device.name,
                               family,ad)
                td['IPv4']=ad
                devices.append(td)
                if device.next:
                    device = device.next.contents
                else:
                    device = False
                
            winpcap_freealldevs(alldevs)
        else:
            raise Exception(errbuf)
        return devices

    def get_network_interfaces():
        dev = winpcap_findalldevs()
        return dev
    def send_frame(out_dev,final_frame,frame_len):
        res=0
        handle= winpcap_open_live(out_dev,1500,1,100)
        if handle is None:
            res=-1
            return res
        else:
            res=winpcap_sendpacket(handle,final_frame,frame_len)
        winpcap_close(handle)
        print("Flow index:%d packet length:%d bytes"%(0,frame_len))
        return res
    pass
