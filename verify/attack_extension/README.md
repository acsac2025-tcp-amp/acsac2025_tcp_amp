The scripts here send additional ACK packets after the initial spoofing attempt. 
We send ACKs to acknowledge all payloads sent by the servers and then send a second HTTP request.

1. Run the initial_collect.py script to learn the server's payload chunk sizes. In later verification, we need to use this knowledge to acknowledge server payloads.
```
iptables -A OUTPUT -p tcp -s $probe_ip --sport 37820 --tcp-flags RST RST -j DROP 
# Drop reset packets sent by the kernel.

python3 initial_collect.py verify_list.csv initial_collect_res.csv $iface $src_mac $dst_mac $probe_ip
# Run the initial collect script to get payload chunk size from the server; The result will be written to initial_collect_res.csv

iptables -D OUTPUT -p tcp -s $probe_ip --sport 37820 --tcp-flags RST RST -j DROP
# Recover the iptable rules.

python3 merge.py initial_collect_res.csv verify_list.csv ext_verify_list_with_size.csv
# Combine the collected window size with the verification list for future use

```

2. Run the verification. This time, we send additional ACK packets to acknowledge server payloads

```
iptables -A OUTPUT -p tcp -s $verify_ip --sport 38409 --tcp-flags RST RST -j DROP 
# Similarly, we first drop outgoing RST packets sent by the port/IP used for spoofing verification.

tcpdump -i $iface ip host $verify_ip and tcp and tcp port 38409 -w 2nd_req_verify_capture.pcap -B 50000 &
# Run tcpdump to capture the packets sent by the server.

python3 verify_all_chunk_2nd_req.py ext_verify_list_with_size.csv verify_2nd_req_log $iface $src_mac $dst_mac $probe_ip $verify_ip 
# Run the verification program

iptables -D OUTPUT -p tcp -s $verify_ip --sport 38409 --tcp-flags RST RST -j DROP 
# Recover the iptable rules
```