import math
from functools import reduce
import sys
from collections import Counter


def gcd_list(diff_list):
    return reduce(math.gcd,diff_list)

def check_repeats(l):
    freq_dict = Counter(l)
    global_proof = False
    for isn in freq_dict.keys():
        if freq_dict[isn]>1:
            odd_pos = False
            prial_pos = False
            for i in range(0,len(l)):
                if l[i]==isn and i%2==0:
                    prial_pos=True
                elif l[i]==isn and i%2==1:
                    odd_pos = True
            if odd_pos==True and prial_pos==True:
                global_proof = True
                break
    return global_proof
    
def get_most_common_first(l):
    most_freq_element,freq = Counter(l).most_common(1)[0]
    return most_freq_element,freq

def get_most_common_three(l):
    return Counter(l).most_common(3)
    
def get_freq_counter(l):
    return Counter(l)


def tagging(isn_list):
    ret_line_potential_D3=""
    ret_line_potential_D="" # sometimes, we delay the decision of whether a host is D1 or D3
    ret_line = "" # the tagging decision
    result_tag = [] # all possible tags we receive for a host, we used this for debugging
    
    raw_isns = [isn_list[i] for i in range(0,len(isn_list))] # raw ISN
    
    number_of_distinct_elements = len(set(isn_list)) # number of distinct raw ISN number
    if len(isn_list) - number_of_distinct_elements > 0:
        repeat_raw_isn = True
    else:
        repeat_raw_isn = False
    # if there are repeat raw ISN in the sequence

    diff_list = [(isn_list[i+1] - isn_list[i]) for i in range(0,len(isn_list)-1)]
    # diff_list = [(isn_list[i+1] - isn_list[i])%2**32 for i in range(0,len(isn_list)-1)]
    diff_of_diff_list = [diff_list[i+1] - diff_list[i] for i in range(0,len(diff_list)-1)] # difference of difference
    
    diff_gcd = gcd_list(diff_list) # greatest common divisor
    num_of_wrap_around = 0 # number of isn wraparounds
    
    current_static_platform_length = 1
    isn_platform_len_list = [] # this is used to track how long is the static ISN used continuously, for SC2 and SC3 and Sa etc.
    for i in range(0,len(isn_list)-1):
        if isn_list[i+1] - isn_list[i] < 0: 
            num_of_wrap_around = num_of_wrap_around + 1 
            isn_platform_len_list.append(current_static_platform_length) 
            current_static_platform_length = 1
            
        elif isn_list[i+1] - isn_list[i] > 0: 
            isn_platform_len_list.append(current_static_platform_length)
            current_static_platform_length = 1
        else:
            current_static_platform_length = current_static_platform_length + 1
            if i ==len(isn_list)-2:
                isn_platform_len_list.append(current_static_platform_length)

    most_common_platform_len,freq = get_most_common_first(isn_platform_len_list) # most common static ISN repeat duration length
    
    most_common_three_diff = get_most_common_three(diff_list) # the top-3 most common ISN difference
    
    sum_zero_and_one_diff = 0 # number of instance where diff=0 or diff=1
    for item in most_common_three_diff:
        if item[0]==0 or item[0]==1:
            sum_zero_and_one_diff = sum_zero_and_one_diff + item[1]    
    
    most_common_diff,most_common_diff_freq = get_most_common_first(diff_list) # get the most common ISN difference


    if repeat_raw_isn==True and len(set(isn_list))==1: # clearly, the S1 tagging is when we only have one distinct raw ISN, we tag the S1 type here already, because later we will use gcd, but gcd for S1 type is 0
        result_tag.append("S1")
        if ret_line=="":
            ret_line = f"S,-,-,-,-,-\n"
        return result_tag,ret_line


    diff_of_diff_list_standarized = [abs(diff_of_diff_list[i])/diff_gcd for i in range(0,len(diff_of_diff_list))] # standarize the difference of difference with abs and gcd
    
    num_increase = 0
    num_decrease = 0
    num_same_diff = 0
    curr_platform_len = 1
    platform_len_list = []
    for i in range(0,len(diff_list)-1):
        if diff_list[i+1] < diff_list[i]:
            num_decrease+=1
            platform_len_list.append(curr_platform_len)
            curr_platform_len=1
        elif diff_list[i+1] > diff_list[i]:
            num_increase+=1
            platform_len_list.append(curr_platform_len)
            curr_platform_len=1
        else:
            num_same_diff+=1
            curr_platform_len=curr_platform_len+1
            if i ==len(diff_list)-2:
                platform_len_list.append(curr_platform_len)
    if len(platform_len_list)==0:
        platform_len_list.append(11)
    # this section is used to track the ISN difference changing trends, we use this for D3 type tagging
    
    min_platform_len = min(platform_len_list) 
    
    most_common_three_dod = get_most_common_three(diff_of_diff_list) # the top-3 most common difference of difference and its frequency
    freq_most_common_three_dod = 0
    for item in most_common_three_dod:
        freq_most_common_three_dod = freq_most_common_three_dod + item[1]

    
    if num_increase>=8 and num_decrease<=2:
        for i in range(0,10):
            if diff_list[i+1] > diff_list[i]:
                continue
            elif diff_list[i+1] < diff_list[i]:
                if i > 0 and diff_list[i+1] * 2 >=diff_list[i] and diff_list[i+1] > diff_list[i-1]:
                    num_increase+=1
                elif i<9 and diff_list[i+1]<0 and diff_list[i+1]%(2**32) > diff_list[i] and diff_list[i+1]%(2**32) < diff_list[i+2]:
                    num_increase+=1
                elif i==0:
                    num_increase+=1
                break
    elif num_decrease>=8 and num_increase<=2:
        for i in range(0,10):
            if diff_list[i+1] < diff_list[i]:
                continue
            elif diff_list[i+1] > diff_list[i]:
                if i<9 and diff_list[i] * 2 >= diff_list[i+1] and diff_list[i+2]<diff_list[i]:
                    num_decrease+=1
    
    most_common_three_diff = get_most_common_three(diff_list) # top-3 most common difference
    most_common_three_freq=0
    for item in most_common_three_diff:
        most_common_three_freq = most_common_three_freq + item[1]

    # D2 tag
    # we check if 0 and 1 diff is majority in the sequence
    if (diff_gcd==1 and sum_zero_and_one_diff>=6) or (diff_gcd==1 and most_common_diff==1 and most_common_diff_freq>=5):
        result_tag.append("D2")
        if ret_line=="":
            ret_line =  f"D2,-,-,-,-,-\n"

    # D3 tag
    if len(set(diff_of_diff_list_standarized))<8 \
        and (((num_increase+num_same_diff)>=10 and not min_platform_len>=3) or ((num_decrease+num_same_diff)>=10 and not min_platform_len>=3)):
        
        most_common_dods = get_most_common_three(diff_of_diff_list)
        possible_dods_per_freq = {}
        for item in most_common_dods:
            if not item[1] in possible_dods_per_freq:
                possible_dods_per_freq[item[1]] = []
        freq_dict = get_freq_counter(diff_of_diff_list)
        for key in freq_dict.keys():
            if freq_dict[key] not in possible_dods_per_freq.keys():
                continue
            possible_dods_per_freq[freq_dict[key]].append(key)
        dod1 = '-'
        dod2 = '-'
        dod3 = '-'

        for key in possible_dods_per_freq.keys():
            possible_dods_per_freq[key].sort(key=abs)
            for value in possible_dods_per_freq[key]:
                if dod1=='-':
                    dod1 = value
                elif dod2=='-':
                    dod2 = value
                elif dod3=='-':
                    dod3 = value


        additional_dod_choices = [0, 1, -1, 2, -2]
        try:
            del additional_dod_choices[additional_dod_choices.index(dod1)]
        except:
            pass


        if dod2=='-' and dod3=='-':
            dod2 = additional_dod_choices[0]
            dod3 = additional_dod_choices[1]

        if dod2!='-' and dod3=='-': 
            try: 
                del additional_dod_choices[additional_dod_choices.index(dod2)]
            except:
                pass

            dod3 = additional_dod_choices[0]
        

        result_tag.append('D3')
        if ret_line=="":
            if get_most_common_first(diff_of_diff_list)[0]==0:
                ret_line_potential_D3 = f"D3,{most_common_platform_len},{dod1},{dod2},{dod3},-\n"
            else:
                ret_line = f"D3,{most_common_platform_len},{dod1},{dod2},{dod3},-\n"


    if (len(set(diff_of_diff_list_standarized))<8 or most_common_three_freq>7): 
        most_common_dods = get_most_common_three(diff_of_diff_list)
        possible_dods_per_freq = {}
        for item in most_common_dods:
            if not item[1] in possible_dods_per_freq: # merge dods with the same frequence together
                possible_dods_per_freq[item[1]] = []

        
        freq_dict = get_freq_counter(diff_of_diff_list)
        for key in freq_dict.keys():
            if freq_dict[key] not in possible_dods_per_freq.keys():
                continue

            possible_dods_per_freq[freq_dict[key]].append(key)

        dod1 = '-'
        dod2 = '-'
        for key in possible_dods_per_freq.keys():
            possible_dods_per_freq[key].sort(key=abs)
            for value in possible_dods_per_freq[key]:
                if value ==0:
                    # the first tried guess is probed_isn+probed_diff+1, so we don't need another 0 here.
                    continue
                if dod1=='-':
                    dod1 = int(value/diff_gcd)
                elif dod2=='-':
                    dod2 = int(value/diff_gcd)

        additional_dod_choices = [1, -1, 2, -2]


        if dod1=='-' and dod2=='-':
            dod1 = additional_dod_choices[0]
            dod2 = additional_dod_choices[1]


        if dod1!='-' and dod2=='-': 
            try: 
                del additional_dod_choices[additional_dod_choices.index(dod1)]
            except:
                pass

            dod2 = additional_dod_choices[0]


        result_tag.append('D')
        if ret_line=="":
            if not (diff_gcd<1000000 and diff_gcd>1):
                ret_line_potential_D = f"D,{most_common_diff},{most_common_platform_len},{diff_gcd},{dod1},{dod2}\n"
            else:
                ret_line = f"D,{most_common_diff},{most_common_platform_len},{diff_gcd},{dod1},{dod2}\n"


    # Sc3 tagging
    if repeat_raw_isn == True and most_common_platform_len>=3 and check_repeats(raw_isns):
        result_tag.append(f"Sc{most_common_platform_len}")
        if ret_line=="":
            ret_line =  f"Sc3,-,-,-,-,-\n"


    # Sc2 tagging
    if repeat_raw_isn == True and most_common_platform_len==2 and check_repeats(raw_isns):
        result_tag.append("Sc2")
        if ret_line=="":
            ret_line = f"Sc2,-,-,-,-,-\n"

    # Sa tagging, we need to check if the same ISN is used for different IPs
    if repeat_raw_isn==True and most_common_platform_len==1 and check_repeats(raw_isns) and len(set(isn_list))<=4:
        result_tag.append("Sa")
        if ret_line=="":
            ret_line = f"Sa,-,-,-,-,-\n"


    if ret_line=="" and ret_line_potential_D3!="":
        ret_line = ret_line_potential_D3


    if ret_line=="" and ret_line_potential_D!="" and (repeat_raw_isn!=True or (repeat_raw_isn==True and check_repeats(raw_isns)==True)):
        ret_line = ret_line_potential_D

    return result_tag,ret_line




if __name__ == "__main__":
    input_file = open(sys.argv[1],'r')
    output_file = open(sys.argv[2],'w')

    for line in input_file:
        line = line.strip()
        line_list = line.split(',')    
        ip = line_list[0]


        raw_isns = [int(line_list[i+1]) for i in range(0,12)]

        ret_v,ret_line = tagging(raw_isns)

        if ret_line!="":
            ret_line = f"{ip},"+ret_line
            output_file.write(ret_line)

