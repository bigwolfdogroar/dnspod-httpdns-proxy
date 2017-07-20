#!/usr/bin/env python3
# encoding: utf-8

#dnspod httpdns proxy
#Only supported TYPE A/AAAA Class IN Standard query

import urllib.request, socket

class httpdns(object):

    def __init__(self, ednsip, ttl=300):
        self.domain=''
        self.ednsip=ednsip
        self.ANCOUNT=0
        self.TTL=(ttl).to_bytes(4, byteorder='big')
        self.answer=b''

    def labelsTOdomain(self, domain):
    # b'\x03www\x06google\x03com\x00' -> 'www.google.com'
        i=0
        r=[]
        for x in domain:
            if i == 0:
                i=x
                x=46 #ord('.') -> 46
            else:
                i=i-1
            r.append(x)
        return bytes(r)[1:-1].decode('ASCII')

    def httprequest(self, Qdata):
        self.domain=self.labelsTOdomain(Qdata[:-4])
        try:
            Rdata_tmp=urllib.request.urlopen('http://119.29.29.29/d?dn=%s&ip=%s' % (self.domain,self.ednsip)).read().split(b';')
        except OSError:
            print('httprequest error')
            return 0, Qdata, b''
        try:
            Rdata=[bytes([int(y) for y in x.split(b'.')]) for x in Rdata_tmp]
        except ValueError:
            print('non answer')
            return 0, Qdata, b''
        return len(Rdata), b''.join([b'\xc0\x0c\x00\x01\x00\x01',self.TTL, b'\x00\x04']).join([Qdata, *Rdata]), Rdata_tmp


class udpdnsserver(object):

    def __init__(self, addr='127.0.0.1', port=53):
        self.udpfd=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.udpfd.bind((addr, port))
        self.addr=()
        self.QID=b''
        self.flags=0

    def input(self):
        data, self.addr=self.udpfd.recvfrom(1500)
        self.flags=int(data[2:4].hex(), 16)            #标志flags 256为标准查询
        self.QID=data[0:2]
        Rcode=0
        if self.flags&0x7800:#0x7800=0111 1000 0000 0000   是否标准查询
            Rcode=4
        elif self.flags&0x8000 != 0:#0x8000=1000 0000 0000 0000 反向查询判断
            Rcode=1
        elif data[4:6] == b'\x00\x01':
            i=0
            for x in data[12:]:
                i=i+1
                if x == 0:
                    break
            if data[12+i:i+16] != b'\x00\x01\x00\x01' and data[12+i:i+16] != b'\x00\x1c\x00\x01':
                Rcode=4
        else:
            Rcode=4
        if Rcode:
            qdata=data[12:]
        else:
            qdata=data[12:i+16]
        return Rcode, qdata

    def output(self, Rcode, Rdata, ANCOUNT=0):
        if Rcode:
            self.flags=self.flags|Rcode
        #self.flags=self.flags|0x8000 #不能直接用请求的flag
        self.flags=0x8080 #这样dnsmasq才会缓存结果
        Rcount=b''.join([b'\x00\x01', ANCOUNT.to_bytes(2, byteorder='big'), b'\x00\x00\x00\x00'])
        Rdata=b''.join([self.QID, self.flags.to_bytes(2, byteorder='big'), Rcount, Rdata])
        self.udpfd.sendto(Rdata, self.addr)

if __name__ == '__main__':
    localserver=udpdnsserver(addr='0.0.0.0')
    dnspod=httpdns(ednsip='224.24.24.45')
    while 1:
        Rcode, Qdata=localserver.input()
        if Rcode:
            print('Rcode==%s,so can\'t into httpdns'%Rcode)
            #localserver.output(Rcode, Rdata=Qdata)
        else:
            ANCOUNT, Rdata, tmp=dnspod.httprequest(Qdata)
            if ANCOUNT:
                localserver.output(Rcode, Rdata, ANCOUNT)
            else:
                print('after httpdns, but no output')
                #pass #localserver.output(Rcode, Rdata=Qdata)
