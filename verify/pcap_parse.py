from scapy.all import *
import scapy
import sys

merged_csv_file = sys.argv[1] # file containing merged tagging result and crawling result 
pcap_file_name = sys.argv[2] # This is the pcap file we captured during verification
output_file_name = sys.argv[3] # parse result
verify_source_ip=sys.argv[4] # source IP used for verification



output_file = open(output_file_name,'w')

reader = scapy.utils.PcapReader(pcap_file_name)

port_list = [38409]



buffer_dict = {}
verify_client_seq = 3182372096

if verify_source_ip=='':
    print('fill in the source ip used in verification')
    exit(0)

f = open(merged_csv_file,'r')
for line in f:
    line_list = line.split('^')
    ip = line_list[0]
    tag = line_list[1]

    if not ip in buffer_dict:
        buffer_dict[ip] = [tag]
f.close()


for pkt in reader:  
    pkt_time = pkt.time
    src_port = pkt['TCP'].sport
    dst_port = pkt['TCP'].dport
    tcp_flags = pkt['TCP'].flags
    seq_range_left = pkt['TCP'].seq
    seq_range_right = pkt['IP'].len - pkt['IP'].ihl*4 - pkt['TCP'].dataofs*4 + pkt['TCP'].seq 
    tot_len = len(pkt)
    src_ip = pkt['IP'].src
    dst_ip = pkt['IP'].dst

    if not ( (src_ip==verify_source_ip and src_port==port_list[0] and dst_port==80 and dst_ip in buffer_dict.keys()) or (dst_ip==verify_source_ip and src_port==80 and dst_port==port_list[0] and src_ip in buffer_dict.keys()) ):
        continue

    if src_port==80:
        relevant_ack = pkt['TCP'].ack - verify_client_seq
        buffer_dict[src_ip].append(f"In,{pkt_time},{tcp_flags},{seq_range_left},{seq_range_right},{relevant_ack},{tot_len};")
        # packet is processed into a tuple contianig its direction, time, flag, seq number range, relevant ack and packet length
    elif dst_port==80: 
        relevant_ack = pkt['TCP'].ack
        buffer_dict[dst_ip].append(f"Out,{pkt_time},{tcp_flags},{seq_range_left},{seq_range_right},{relevant_ack},{tot_len};")
        

print('all packets are read')

for ip in buffer_dict.keys():
    output_file.write(f"{ip};{buffer_dict[ip][0]};")
    for pkt_log in buffer_dict[ip][1:]:
        output_file.write(pkt_log)
    output_file.write('\n')        
output_file.close()


import os
os._exit(0)