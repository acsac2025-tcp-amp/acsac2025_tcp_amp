from scapy.all import *
from random import randint
from random import sample
import time
from threading import Thread
import socket
from threading import Lock

class Sender:
    def __init__(self,src_mac,dst_mac,src_ip,src_port):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = src_ip
        self.src_port = src_port
        self.eth_header = Ether(src=src_mac,dst=dst_mac)

def build_syn_packet(sender: Sender,dst_ip,ack=0,dport=80,seq=3182372096) -> bytes:
    pac = bytes(
        Ether(
            bytes(
                sender.eth_header/IP(src=sender.src_ip,dst=dst_ip)/TCP(sport=sender.src_port,dport=dport,flags='S',seq=seq,ack=ack,window=64240)
            )
        )
    )
    return pac

def build_syn_packet_large_mss(sender: Sender,dst_ip,ack=0,dport=80,seq=3182372096) -> bytes:
    pac = bytes(
        Ether(
            bytes(
                sender.eth_header/IP(src=sender.src_ip,dst=dst_ip)/TCP(sport=sender.src_port,dport=dport,flags='S',seq=seq,ack=ack,window=64240,options=[('MSS',1460)])
            )
        )
    )
    return pac


def build_rst_packet(sender:Sender,dst_ip,ack=0,dport=80,seq=3182372097) -> bytes:
    pac = bytes(
        Ether(
            bytes(
                sender.eth_header/IP(
                    src=sender.src_ip,dst=dst_ip
                    )/TCP(
                        sport=sender.src_port,dport=dport,flags='R',seq=seq,ack=ack,window=64240
                    )
            )
        )
    )
    return pac

def build_ack_packet(sender:Sender,dst_ip,ack,dport=80,seq=3182372097) -> bytes:
    pac = bytes(
        Ether(
            bytes(
                sender.eth_header/IP(
                    src=sender.src_ip,dst=dst_ip
                    )/TCP(
                        sport=sender.src_port,dport=dport,flags='A',seq=seq,ack=(ack)%2**32,window=64240
                    )
            )
        )   
    )
    return pac
    
def build_ack_with_payload_packet(sender:Sender,dst_ip,ack,resource_path,host,dport=80,seq=3182372097) -> bytes:
    if host=='None' or host=='' or host==None:
        payload_template = f'GET {resource_path} HTTP/1.1\r\nHost: {dst_ip}\r\nUser-Agent: -\r\nAccept: */*\r\nAccept-Encoding: identity\r\n\r\n'
    else:
        host = host.strip()
        payload_template = f'GET {resource_path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: -\r\nAccept: */*\r\nAccept-Encoding: identity\r\n\r\n'
    
    payload_template = bytes(payload_template,'ascii')    

    pac = bytes(
        Ether(
            bytes(
                    sender.eth_header/IP(
                        src=sender.src_ip,dst=dst_ip
                        )/TCP(
                            sport=sender.src_port,dport=dport,flags='PA',seq=seq,ack=(ack)%2**32,window=64240
                            )/payload_template
                        )
                )
        )
    
    return pac

