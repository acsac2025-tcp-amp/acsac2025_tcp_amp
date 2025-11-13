After obtaining the "ISN_set_filterd.csv" from the ISN scanner (/scan folder), use the following script to run clustering over the collected ISNs. When the ISN dataset is too large, consider using a fraction of it, e.g., 10 million hosts' ISN sequences.

1. Run clustering on the ISN dataset
```
python3 cluster.py ISN_set_filterd.csv cluster_result.csv 1>/dev/null 2>/dev/null
```

2. Filter suspicious clusters for manual examination
```
python3 filtering.py cluster_result.csv
```

