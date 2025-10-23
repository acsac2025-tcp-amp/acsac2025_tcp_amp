For hosts that are suspicious of having a predictable ISN pattern (from /tagging), we run the crawler script to search for large HTTP resources on these hosts.


1. Run crawler on the list of tagged IPs.
```
python3 crawler.py tagged_ip_list.csv crawl_result.csv $LOCAL_IP 2>/dev/null
```

The "tagged_ip_list.csv" is a list of tagged IPs; an example is provided. 
$LOCAL_IP is the IP to be used by the crawler.


2. Once the resource result is obtained, we merge the tagging result with the resource size for later verification. 
```
python3 merge_result.py crawl_result.csv tagging_result.csv
```

The merged result is written to "verify_list.csv"; we will later use this file for simulated verification.