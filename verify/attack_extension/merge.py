import pandas as pd
import sys
chunk_df = pd.read_csv(sys.argv[1],header=None,names=['ip','chunk_sizes'],sep=';')
sample_df = pd.read_csv(sys.argv[2],header=None,names=['ip','tag','p1','p2','p3','p4','p5','model','path','size','host'],sep='^')
merged = pd.merge(chunk_df,sample_df,on='ip',how='inner')
merged = merged.drop(['model','size'],axis=1)
merged.to_csv(sys.argv[3],index=None,sep='^',header=None)

