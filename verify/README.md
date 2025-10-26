From the previous steps, we have obtained the list of IPs that are suspicious of being exploited in an amplification attack. We now run simulated verification and estimate the amplification factor.

1. For later verification, we will use port 38409; we drop the outgoing RST packets to behave like an unresponsive victim. 
```
iptables -A OUTPUT -p tcp -s $verify_ip --sport 38409 --tcp-flags RST RST -j DROP 
```

2. Use tcpdmp to capture the traffic received from the remote server.
```
tcpdump -i $iface ip host $verify_ip and tcp and tcp port 38409 -w verify_capture.pcap -B 50000 &
```


3. Run the verification program
```
python3 verify.py verify_list.csv verify_log $iface $src_mac $dst_mac $probe_ip $verify_ip

# $probe_ip is the IP controlled by the attacker. The attacker uses this IP to probe for fresh ISNs from the server. $verify_ip is then used by the attacker to send SYN and ACK packets with the guessed ISN to establish the connection.
```

4. Recover the iptable rules.
```
iptables -D OUTPUT -p tcp -s $verify_ip --sport 38409 --tcp-flags RST RST -j DROP 
```


5. Evaluate the collected pcap file and estimate the amplification factor
```
python3 pcap_parse.py verify_list.csv verify_capture.pcap verify_capture_parsed $verify_ip
# We parse the pcap file for later processing.


python3 amp_calculate.py verify_capture_parsed amp_log 
# Run the amp_calculation script to calculate the estimated amplification factor under different RTT or when the victim is unresponsive.

python3 get_success_rate.py amp_log verify_list.csv
# Check the success rate per pattern type

python3 draw.py amp_log tagging_result.csv
# Run the draw.py to draw the violin plot to show the average/median amplification factor per pattern type for unresponsive victims and responsive victims with 150ms RTT.

```
