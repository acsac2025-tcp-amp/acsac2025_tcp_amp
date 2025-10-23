Before running the customized scanner to send 12 SYN probes to servers, zmap should be used to identify servers listening on the target port. 

1. Compile the scanner script
```
gcc -O2 -std=gnu11 -Wno-error -Wno-incompatible-pointer-types -Wno-pointer-sign packet_builder.c packet_builder.h scanner.c -o scanner 2>/dev/null
```

2. Run tcpdump to capture response SYN-ACK packets triggered by the scanner
```
tcpdump -S -n -i $iface tcp src port 80 and dst portrange 37890-52500 and not src host $PROBE_IP_1 and not src host $PROBE_IP_2 and "tcp[tcpflags]&(tcp-syn|tcp-ack)==(tcp-syn|tcp-ack)" -w scanner_capture.pcap &

# PROBE_IP_1 and PROBE_IP_2 are the two IPs used for probing
```

3. Run the scanner
```
sudo ./scanner $iface $SRC_MAC $GATEWAY_MAC $PROBE_IP_1 $PROBE_IP_2
```

The scanner will read the file "zmap_scan_result.csv" to obtain the list of IPs for scanning. 
An example file is provided in the /scan folder.
We use 12 distinct source ports and alternate two source IPs to send SYN probes to the server.


4. Upon finishing, dump collected ISNs from the pcap file
```
python3 dump_ISN.py scanner_capture.pcap ISN_set.csv
```

5. Use grep to remove those IPs we failed to capture all 12 ISNs.
```
grep -v "\-1" ISN_set.csv > ISN_set_filterd.csv
```
