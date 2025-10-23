import pandas as pd
import sys

resource_df = pd.read_csv(sys.argv[1],header=None,names=['ip','model','path','size','host'],sep='^')
tag_df = pd.read_csv(sys.argv[2],header=None,names=['ip','tag','p1','p2','p3','p4','p5'])

merged_df = pd.merge(tag_df,resource_df,on='ip',how='inner')
merged_df = merged_df.drop_duplicates('ip')

merged_df = merged_df[merged_df['size']>1000]
merged_df.to_csv('verify_list.csv',index=False,header=None,sep='^')

