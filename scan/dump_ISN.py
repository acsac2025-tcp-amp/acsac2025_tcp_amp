from scapy.all import *
import scapy
import sys

dict_for_ips = {}

in_f_name = sys.argv[1] # pcap containing the scanning result captured when running the scanner
out_f_name = sys.argv[2] # the file to write the ISN for each host, later we will do clustering/tagging on this file

reader = scapy.utils.PcapReader(in_f_name)
f = open(out_f_name,'w')

finished = False

ip1 = ""
ip2 = ""

port_to_index_map = { 
                      37892:0,
                      38925:1,
                      40000:2,
                      43125:3,
                      44597:4,
                      45125:5,
                      45832:6,
                      48125:7,
                      49101:8,
                      50000:9,
                      50372:10,
                      52443:11
                    }
# ports used for scanning


while(True):
    try:
        pkt = None
        pkt = reader.read_packet()
    except:
        

        for key in dict_for_ips.keys():
            item = dict_for_ips[key]
            try:
                line = '%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n' % (key,item[0],item[1],item[2],item[3],item[4],item[5],item[6],item[7],item[8],item[9],item[10],item[11])
                f.write(line)
            except Exception as e:
                continue
        f.close()
        exit(0)
        

    try:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport
        seq = pkt[TCP].seq
        flags= pkt[TCP].flags
    except:
        continue

    if not flags=='SA':
        continue

    if src_ip in dict_for_ips.keys():
        try:
            if dict_for_ips[src_ip][port_to_index_map[dst_port]]==-1:
                dict_for_ips[src_ip][port_to_index_map[dst_port]] = seq
                dict_for_ips[src_ip][-1] = dict_for_ips[src_ip][-1] + 1
        except:
            continue

    else:
        dict_for_ips[src_ip] = [-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,1]
        try:
            dict_for_ips[src_ip][port_to_index_map[dst_port]] = seq
        except:
            continue

        if len(dict_for_ips.keys())>=25000: 
            key_list = []
            c = 10
            for key in dict_for_ips.keys():
                if dict_for_ips[key][-1] == 12:
                    # we already got all 12 numbers and should stop collecting for this particular IP
                    key_list.append(key)
                    c = c - 1
                else:
                    if c>0:
                        key_list.append(key)
                        c = c - 1
                    else:
                        continue
            
            
            for key in key_list:
                item = dict_for_ips[key]
                line = '%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n' % (key,item[0],item[1],item[2],item[3],item[4],item[5],item[6],item[7],item[8],item[9],item[10],item[11])
                f.write(line)

            for key in key_list:
                del dict_for_ips[key]    

