import pandas as pd
import numpy as np
import sys



def map_to_small_space(sequences):
    for sequence in sequences:
        v = 0
        mapping = {}
        for i in range(len(sequence)):
            if sequence[i] in mapping.keys():
                sequence[i] = mapping[sequence[i]]
            else:
                mapping[sequence[i]] = v
                sequence[i] = v
                v +=1

def get_transition_matrix(sequence):
    states = set(sequence)
    t_matrix = np.zeros((len(states), len(states)))
    for i in range(len(sequence)-1):
        state_1 = sequence[i]
        state_2 = sequence[i+1]
        t_matrix[state_1][state_2] += 1
    return t_matrix

def get_n_most_likely_continuations(t_matrix, n, elem):
    transitions = t_matrix[elem]
    continuations = transitions.argsort()[-n:][::-1]
    return continuations


def use_MARKOV(cluster_frame,use_diff,diff_degree):
    n_predictions = 1
    sequences = cluster_frame.iloc[:, 8:20].values.tolist()
    
    if use_diff:
        if diff_degree==1:
            for i in range(0,len(sequences)):
                temp = [(sequences[i][m+1]-sequences[i][m])%2**32 for m in range(0,len(sequences[i])-1)]
                sequences[i] = temp
        elif diff_degree==2:
            for i in range(0,len(sequences)):
                temp = [(sequences[i][m+1]-sequences[i][m])%2**32 for m in range(0,len(sequences[i])-1)]
                temp2 = [temp[m+1]-temp[m] for m in range(0,len(temp)-1)]
                sequences[i] = temp2

    sequences = np.array(sequences,dtype=np.int64)

    map_to_small_space(sequences)
    correct=0

    for sequence in sequences:
        t_matrix = get_transition_matrix(sequence[:-1])
        # build the transition matrix on the first n-1 elements of a sequence

        predictions = get_n_most_likely_continuations(t_matrix, n_predictions, sequence[-2])
        # use the second last element in the sequence to predict the last

        actual = int(sequence[-1])
        for pred in predictions:
            pred = int(pred)
            if actual==pred:
                correct+=1
                break
        
        if correct>0:
            break
        # if we found any potentially predictable sequence, we skip the rest and mark the cluster as suspious for manual examination.
    

    if correct > 0:
        return True
    else:
        return False



if __name__ == "__main__":
    min_cluster_size = 25

    input_file = sys.argv[1]

    column_names = ["host", "repeat_raw_isn", "count_wrap", "diff_gcd", "corrcoef", "most_common_diff_of_diff", "freq", "l", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "cluster"]
    df = pd.read_csv(input_file, delimiter="\t", names=column_names)
    df['cluster'] = df['cluster'].str.rstrip('*').astype(int)
    df = df[df['cluster'] != -1]
    n_clusters = df['cluster'].max() + 1 
    
    suspicious_cluster_list = []
    for i in range(0,n_clusters):
        cluster_frame = df[df["cluster"] == i]
        cluster_size = len(cluster_frame)
        if cluster_size<min_cluster_size:
            continue
            # we only check large clusters
        
        if use_MARKOV(cluster_frame,True,2) or use_MARKOV(cluster_frame,True,1) or use_MARKOV(cluster_frame,False,0):
            suspicious_cluster_list.append(str(i)+'*')
        
    suspicious_cluster_list.sort()
    print('number of suspicious clusters:',len(suspicious_cluster_list))
    print(suspicious_cluster_list)
    
        




