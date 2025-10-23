import math
from functools import reduce
import pandas as pd
import numpy as np
import sys
from sklearn.cluster import DBSCAN
import scipy
from collections import Counter
import multiprocessing



def gcd_list(diff_list):
    return reduce(math.gcd,diff_list)

def find_most_common(diff_list):
    counter = Counter(diff_list)
    most_common_element,freq = counter.most_common(1)[0]
    return most_common_element,freq


input_file = sys.argv[1] # input file is the csv file containing all 12 ISNs we collected from hosts. 
output_file = open(sys.argv[2],'w') # file to write the clustering result


ip_label_list = []
dataset = []


dataset = pd.read_csv(input_file,header=None)
dataset = dataset.drop_duplicates([0],keep='first')


ip_label_list = dataset.iloc[:, 0].tolist()
dataset = dataset.drop(dataset.columns[0],axis=1)
dataset = dataset.values.tolist()


dataset_len = len(dataset)
num_of_threads = 20


def worker(index):
    result_list = []
    item_counter =0
    left = index*int(dataset_len/num_of_threads)
    right = min(index*int(dataset_len/num_of_threads)+int(dataset_len/num_of_threads),dataset_len)
    if index == num_of_threads-1:
        right = dataset_len
    
    for ind in range(left,right):
        item_counter = item_counter + 1
        isn_list = dataset[ind]
        diff_gcd=1
        count_wrap = 0
        repeat_raw_isn = 0
        if len(set(isn_list))!=len(isn_list):
            repeat_raw_isn=100 
        diff_list = []
        
        for i in range(0,len(isn_list)-1):
            diff = isn_list[i+1] - isn_list[i]
            if diff < 0:
                count_wrap = count_wrap + 1
                diff_list.append(diff + 2**32)
            else:
                diff_list.append(diff)
        
        diff_gcd = gcd_list(diff_list)


        corrcoef = pd.Series(diff_list).autocorr(lag=1)

        
        if np.isnan(corrcoef):
            corrcoef=-99


        if diff_gcd==0:
            diff_gcd=1

        dod_list = [int(abs(diff_list[i+1]-diff_list[i])/diff_gcd) for i in range(0,len(diff_list)-1)]
        most_common_diff_of_diff, freq = find_most_common(dod_list)
        
        
        result_list.append([repeat_raw_isn, # repeat marker
                    count_wrap, # num of wrap around
                    diff_gcd, # gcd
                    corrcoef*10,  # correlation coefficient
                    most_common_diff_of_diff, # most common difference of difference
                    freq, # frequence
                    len(set(isn_list))]) # number of distinct element
            
    queue.put((index,result_list))


threads = []
clustering_stats_lists = []
queue = multiprocessing.Queue()
for i in range(0,num_of_threads):
    process = multiprocessing.Process(target=worker,args=(i,))
    threads.append(process)
    process.start()



for _ in range(num_of_threads):
    clustering_stats_lists.append(queue.get())

for thread in threads:
    thread.join()


sorted_list = sorted(clustering_stats_lists,key=lambda x:x[0])
clustering_stats_list = []
for l in sorted_list:
    clustering_stats_list.extend(l[1])


print('finish processing')
clustering_stats_list = pd.DataFrame(np.array(clustering_stats_list))

model = DBSCAN(eps=3,min_samples=2,n_jobs=10).fit(clustering_stats_list)
cluster_labels = model.labels_
clustering_stats_list = np.array(clustering_stats_list)
print('finish clustering')

for i in range(0,len(ip_label_list)):
    line = "%s\t%d\t%d\t%d\t%.2f\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d*\n" % (ip_label_list[i],
                                                    clustering_stats_list[i][0],
                                                    clustering_stats_list[i][1],
                                                    clustering_stats_list[i][2],
                                                    clustering_stats_list[i][3],
                                                    clustering_stats_list[i][4],
                                                    clustering_stats_list[i][5],
                                                    clustering_stats_list[i][6],
                                                    dataset[i][0],dataset[i][1],dataset[i][2],dataset[i][3],
                                                    dataset[i][4],dataset[i][5],dataset[i][6],dataset[i][7],
                                                    dataset[i][8],dataset[i][9],dataset[i][10],dataset[i][11],
                                                    cluster_labels[i])
    
    output_file.write(line)



