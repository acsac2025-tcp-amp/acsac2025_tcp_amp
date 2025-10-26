import pandas as pd
import sys


amp_log_df = pd.read_csv(sys.argv[1],header=None,names=['ip','success','amp_50','amp_100','amp_200','amp_150','amp_500','amp_1000','amp_2000','amp_no_limit'],sep=',')
amp_log_df = amp_log_df.drop_duplicates('ip')
# Whether spoofing is successful is saved in the amplification factor calculation result.

verify_list_df = pd.read_csv(sys.argv[2],header=None,names=['ip','tag','p1','p2','p3','p4','p5','model','path','size','host'],sep='^')
verify_list_df = verify_list_df.drop_duplicates('ip')
# we read the list of hosts we performed verification

merged_df = pd.merge(verify_list_df,amp_log_df,on=['ip'],how='inner')
tag_size_df = merged_df.groupby('tag').size().reset_index()
tag_size_df.columns = ['tag','size']
# merge the two dfs and group by the tag so we know the number of hosts that is verifiable with each pattern.

print('tag,number of successful spoof,number of all hosts of this type,success rate')
for entry in tag_size_df.values:
    tag = entry[0]
    host_num_under_tag = entry[1]

    success_num_under_tag = merged_df[(merged_df['tag']==tag) & (merged_df['success']==True)].shape[0]
    print(tag, success_num_under_tag, host_num_under_tag, success_num_under_tag/host_num_under_tag)
