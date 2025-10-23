import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import sys
import seaborn as sns
import plotly.express as px


def compute_cdf(data):
    data_sorted = np.sort(data)
    cdf = np.arange(1, len(data_sorted)+1) / len(data_sorted)
    return data_sorted, cdf

amp_calculation_df = pd.read_csv(sys.argv[1],header=None,names=['ip','success','amp_50','amp_100','amp_200','amp_150','amp_500','amp_1000','amp_2000','amp_no_limit'],sep=',')
amp_calculation_df = amp_calculation_df.drop_duplicates(['ip'])

tag_df = pd.read_csv(sys.argv[2],header=None,names=['ip','tag','p1','p2','p3','p4','p5'])
tag_df = tag_df.drop(['p1','p2','p3','p4','p5'],axis=1)
tag_df = tag_df.drop_duplicates(['ip'])

merged_df = pd.merge(amp_calculation_df,tag_df,on='ip',how='inner')
merged_df = merged_df.drop(merged_df[merged_df['success']==False].index)


tag_success = {
    'S':[0,0],
    'Sc2':[0,0],
    'Sc3':[0,0],
    'Sa':[0,0],
    'D':[0,0],
    'D2':[0,0],
    'D3':[0,0]
}

amp50_list = []
amp100_list = []
amp200_list = []
amp150_list = []
amp500_list = []
amp1000_list = []
amp2000_list = []
amp_all_list = []

per_type_150_list = {
    "S":[],
    "Sc2":[],
    "Sc3":[],
    "Sa":[],
    "D":[],
    "D2":[],
    "D3":[],
    'All':[]
}
per_type_silent_list = {
    "S":[],
    "Sc2":[],
    "Sc3":[],
    "Sa":[],
    "D":[],
    "D2":[],
    "D3":[],
    'All':[]
}


for value in merged_df.values:
    tag = value[-1]
    per_type_150_list[tag].append(value[5])
    per_type_silent_list[tag].append(value[9])
    per_type_150_list['All'].append(value[5])
    per_type_silent_list['All'].append(value[9])

for key in per_type_150_list.keys():
    try:
        print('per type max before exclude outlier 150ms',key,max(per_type_150_list[key]))
        print('per type max before exclude outlier silent',key,max(per_type_silent_list[key]))
    except Exception as e:
        pass

for key in per_type_150_list.keys():
    per_type_150_list[key].sort()
    per_type_silent_list[key].sort()
    per_type_150_list[key] = per_type_150_list[key][0:int(0.99*len(per_type_150_list[key]))]
    per_type_silent_list[key] = per_type_silent_list[key][0:int(0.99*len(per_type_silent_list[key]))]



data = pd.DataFrame({
    "Pattern Type":(['All']*len(per_type_silent_list['All']))+
    (['D1'] * len(per_type_silent_list['D'])) + 
    (['D2'] * len(per_type_silent_list['D2'])) + 
    (['D3'] * len(per_type_silent_list['D3'])) +
    (['S1'] * len(per_type_silent_list['S'])) + 
    (['SCx'] * len(per_type_silent_list['Sc2']+per_type_silent_list['Sc3'])) + 
    (['Sa'] * len(per_type_silent_list['Sa'])),
    
    "Amplification Factor":np.concatenate([
        np.array(per_type_silent_list['All']),
        np.array(per_type_silent_list['D']),
        np.array(per_type_silent_list['D2']),
        np.array(per_type_silent_list['D3']),
        np.array(per_type_silent_list['S']),
        np.array(per_type_silent_list['Sc2']+per_type_silent_list['Sc3']),
        np.array(per_type_silent_list['Sa']),
    ])
})



plt.figure(figsize=(10,6))
sns.violinplot(x='Pattern Type',y='Amplification Factor',data=data,width=1.7)
plt.ylim(0,50)
plt.xticks(fontsize=18)
plt.yticks(np.arange(0,55,5),fontsize=18)
plt.xlabel("Pattern Type", fontsize=18)
plt.ylabel("Amplification Factor", fontsize=18)


means = data.groupby("Pattern Type")["Amplification Factor"].mean()
medians = data.groupby('Pattern Type')['Amplification Factor'].median()
for i, (category, mean) in enumerate(means.items()):
    plt.text(i, 54, f'A:{mean:.2f}', color='black', ha='center', va='center',fontsize=18)
    
for i, (category, med) in enumerate(medians.items()):
    plt.text(i, 51, f'M:{med:.2f}', color='black', ha='center', va='center',fontsize=18)


plt.savefig('unresponsive.png')



data = pd.DataFrame({
    "Pattern Type":(['All']*len(per_type_150_list['All']))+
    (['D1'] * len(per_type_150_list['D'])) + 
    (['D2'] * len(per_type_150_list['D2'])) + 
    (['D3'] * len(per_type_150_list['D3'])) +
    (['S1'] * len(per_type_150_list['S'])) + 
    (['SCx'] * len(per_type_150_list['Sc2']+per_type_150_list['Sc3'])) + 
    (['Sa'] * len(per_type_150_list['Sa'])),
    
    "Amplification Factor":np.concatenate([
        np.array(per_type_150_list['All']),
        np.array(per_type_150_list['D']),
        np.array(per_type_150_list['D2']),
        np.array(per_type_150_list['D3']),
        np.array(per_type_150_list['S']),
        np.array(per_type_150_list['Sc2']+per_type_150_list['Sc3']),
        np.array(per_type_150_list['Sa']),
    ])
})


plt.figure(figsize=(10,6))
sns.violinplot(x='Pattern Type',y='Amplification Factor',data=data,width=1.7)
plt.ylim(0,50)
plt.xticks(fontsize=18)
plt.yticks(np.arange(0,55,5),fontsize=18)
plt.xlabel("Pattern Type", fontsize=18)
plt.ylabel("Amplification Factor", fontsize=18)

means = data.groupby("Pattern Type")["Amplification Factor"].mean()
medians = data.groupby('Pattern Type')['Amplification Factor'].median()
for i, (category, mean) in enumerate(means.items()):
    plt.text(i, 54, f'A:{mean:.2f}', color='black', ha='center', va='center',fontsize=18)
    
for i, (category, med) in enumerate(medians.items()):
    plt.text(i, 51, f'M:{med:.2f}', color='black', ha='center', va='center',fontsize=18)


plt.savefig('responsive.png')
