from scapy.all import *
import time
from threading import Thread
import sys
from verify_model import *

USE_LARGE_MSS = True
sampled_hosts_file = sys.argv[1]
result_output = sys.argv[2]
log_file = open(result_output,'w')
log_file.write('')
log_file.close()

iface = sys.argv[3]
src_mac = sys.argv[4]
dst_mac = sys.argv[5]
src_ip1 = sys.argv[6]



f = open(sampled_hosts_file,'r')
lines = f.readlines()
f.close()

eth_header = Ether(src=src_mac,dst=dst_mac)
dport = 80
probe_rsp_buffer = {}



def sniffer_callback(packet):
    try:
        ip = packet['IP'].src
        dport = packet['TCP'].dport
        key = ip

        if not key in probe_rsp_buffer.keys():
            return
        
        flags = str(packet['TCP'].flags)
        seq_left = packet['TCP'].seq
        seq_right = packet['IP'].len - packet['IP'].ihl*4 - packet['TCP'].dataofs*4 +seq_left
        
        if flags=='SA' and probe_rsp_buffer[key][0]==None:
            probe_rsp_buffer[key][0] = seq_left
        elif not ('S' in flags or 'R' in flags or 'F' in flags) and probe_rsp_buffer[key][0]!=None:
            # we only consider non-FIN, non-RST and non-SYN packet after received from server.
            # we also ignore FIN packet, as if the server already sends FIN, even we acknowledge it we cannot continue using the connection 
            probe_rsp_buffer[key][1].append(seq_right)  

        return
    except Exception as e:
        pass

def sniffer():
    filter_exp = f"tcp src port 80 and tcp dst port {37820} and ip host {src_ip1}"
    sniff(iface=iface,prn=sniffer_callback,filter=filter_exp)

thread_sniffer = Thread(target=sniffer)
thread_sniffer.start()
time.sleep(2)
load_layer('http')
raw_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
raw_socket.bind((iface,0))



ip_path_set = []

for line in lines:
    line_list = line.split('^')
    ip_path_set.append((line_list[0],line_list[-3].split(line_list[0])[1],line_list[1],line_list[-1]))


for ip_path in ip_path_set:
    seq = 3182372096
    ip = ip_path[0]
    resource_path = ip_path[1]
    if resource_path=='':
        resource_path = '/'
    tag = ip_path[2]
    hostname = ip_path[3]

    sender = Sender(src_mac,dst_mac,src_ip1,37820)


    if hostname=='None' or hostname=='' or hostname==None:
        payload_template = f'GET {resource_path} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: -\r\nAccept: */*\r\nAccept-Encoding: identity\r\n\r\n'
    else:
        hostname = hostname.strip()
        payload_template = f'GET {resource_path} HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: -\r\nAccept: */*\r\nAccept-Encoding: identity\r\n\r\n'


    if USE_LARGE_MSS==False:
        tcp_syn = build_syn_packet(sender,ip,0,80,seq)
    else:
        tcp_syn = build_syn_packet_large_mss(sender,ip,0,80,seq)

    key = ip
    probe_rsp_buffer[key] = [None,[]]
    raw_socket.send(tcp_syn)
    time.sleep(0.35)

    if type(probe_rsp_buffer[key][0])!=int:
        del probe_rsp_buffer[key]
        continue
    
    isn = probe_rsp_buffer[key][0]


    tcp_ack = build_ack_packet(sender,ip,isn+1,80,seq+1)
    tcp_request = build_ack_with_payload_packet(sender,ip,isn+1,resource_path,hostname,80,seq+1)


    old_len = len(probe_rsp_buffer[key][1]) # when the sniffer callback found a new packet, we push its seq_end to the list in probe_rsp_buffer[key][1]
    raw_socket.send(tcp_ack)
    time.sleep(0.005)
    raw_socket.send(tcp_request)
    payload_length_line = f"{ip};["
    
    
    current_max = isn+1 # after sending SYN-ACK, the server next would use ISN + 1
    while(True):
        time.sleep(0.8)
        if len(probe_rsp_buffer[key][1])==0:
            break
 
        if max(probe_rsp_buffer[key][1])>current_max:
            current_max = max(probe_rsp_buffer[key][1])
            # we have payload grow in the last round
            # otherwise we should give up
        else:
            break

        if old_len==len(probe_rsp_buffer[key][1]):
            break
        else:
            old_len=len(probe_rsp_buffer[key][1])
        

        tcp_ack = build_ack_packet(sender,ip,max(probe_rsp_buffer[key][1]),80,seq+1+len(payload_template))
        # acknowledge the new known largest sequence 
        raw_socket.send(tcp_ack)
        payload_length_line = payload_length_line + str(current_max-(isn+1))+','

    log_file = open(result_output,'a') # the file containing the final result, i.e., chunk sizez collected from a particular host
    log_file.write(payload_length_line[:-1]+']\n')
    log_file.close()
    del probe_rsp_buffer[key]

import os
os._exit(0)