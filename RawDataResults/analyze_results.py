"""SplitPoison 基准 6000-cell 结果统计分析(RQ1-RQ5)。
输出: analysis_report.txt(数值报告) + raw_executions.csv(逐次执行) + cell_asr.csv(单元) + owasp_asr.csv + operator_asr.csv。
RQ6(动态vs静态)/RQ7(防御)数据未采集, 不在此脚本。"""
import json, glob, re, sys
import numpy as np, pandas as pd
from scipy.stats import fisher_exact, chi2
from statsmodels.stats.proportion import proportion_confint
from statsmodels.stats.multitest import multipletests
import statsmodels.api as sm, statsmodels.formula.api as smf

OUT="/tmp/jss_analysis/"
AG=["claude_code","codex_cli","gemini_cli","openhands"]
ML=["claude-sonnet-4-6","glm-5_1","MiniMax-M2_7","gemini-3-pro","gpt-5_3-codex"]
MLn={"claude-sonnet-4-6":"Sonnet4.6","glm-5_1":"GLM5.1","MiniMax-M2_7":"MiniMax2.7","gemini-3-pro":"Gemini3Pro","gpt-5_3-codex":"GPT5.3"}
rows=[]
for v in glob.glob("mutations/*/round_*/verdict.json"):
    p=v.split("/"); mid=p[1]; rd=p[2].replace("round_","")
    ag=None
    for a in AG:
        if rd.startswith(a+"__"): ag=a; smodel=rd[len(a)+2:]; break
    if ag is None: continue
    try: d=json.load(open(v))
    except: continue
    seed=re.sub(r"__M[0-9].*","",mid); op=re.search(r"(M[0-9])",mid).group(1); owasp=seed.split("_")[0]
    rows.append((ag,smodel,seed,op,owasp,int(bool(d.get("elicited")))))
df=pd.DataFrame(rows,columns=["agent","model","seed","op","owasp","e"])
df.to_csv(OUT+"raw_executions.csv",index=False)
L=[]
def P(s=""): L.append(s); print(s)
def wil(k,n):
    if n==0: return (float("nan"),)*3
    lo,hi=proportion_confint(k,n,0.05,"wilson"); return 100*k/n,100*lo,100*hi
P("="*70); P("SplitPoison 基准结果统计  N=%d  elicited=%d  聚合ASR=%.2f%%"%(len(df),df.e.sum(),100*df.e.mean())); P("="*70)
P("\n[RQ1] 单元 ASR + Wilson 95%% CI"); cell={}; cr=[]
for a in AG:
  for m in ML:
    s=df[(df.agent==a)&(df.model==m)]; k=int(s.e.sum()); n=len(s); cell[(a,m)]=(k,n); pe,lo,hi=wil(k,n)
    P("  %-12s x %-10s %3d/%d ASR=%.1f%% [%.1f,%.1f]"%(a,MLn[m],k,n,pe,lo,hi)); cr.append((a,MLn[m],k,n,round(pe,2),round(lo,2),round(hi,2)))
pd.DataFrame(cr,columns=["agent","model","elicited","n","asr","wilson_lo","wilson_hi"]).to_csv(OUT+"cell_asr.csv",index=False)
P("\n[RQ1/RQ3] 边际 ASR")
for a in AG: s=df[df.agent==a]; pe,lo,hi=wil(int(s.e.sum()),len(s)); P("  agent %-12s ASR=%.1f%% [%.1f,%.1f]"%(a,pe,lo,hi))
for m in ML: s=df[df.model==m]; pe,lo,hi=wil(int(s.e.sum()),len(s)); P("  model %-10s ASR=%.1f%% [%.1f,%.1f]"%(MLn[m],pe,lo,hi))
ca={k:cell[k][0]/cell[k][1] for k in cell}; mx=max(ca,key=ca.get); mn=min(ca,key=ca.get)
agA=[df[df.agent==a].e.mean() for a in AG]; mlA=[df[df.model==m].e.mean() for m in ML]
P("\n  单元最高 %s=%.1f%%  最低 %s=%.1f%%  跨度比=%.2fx"%(mx,100*ca[mx],mn,100*ca[mn],ca[mx]/ca[mn]))
P("  agent 轴跨度比=%.2fx  model 轴跨度比=%.2fx"%(max(agA)/min(agA),max(mlA)/min(mlA)))
P("\n[RQ1] 单元两两 Fisher + BH-FDR 可分辨性")
keys=[(a,m) for a in AG for m in ML]; pv=[]; dd=[]
for i in range(len(keys)):
  for j in range(i+1,len(keys)):
    k1,n1=cell[keys[i]]; k2,n2=cell[keys[j]]; _,pp=fisher_exact([[k1,n1-k1],[k2,n2-k2]]); pv.append(pp); dd.append(abs(k1/n1-k2/n2))
rej,_,_,_=multipletests(pv,0.05,"fdr_bh"); und=[d for d,r in zip(dd,rej) if not r]
P("  %d 对中 %d 对可分辨(%.1f%%), %d 对不可分辨"%(len(pv),int(rej.sum()),100*rej.mean(),int((~rej).sum())))
if und: P("  不可分辨对 |Δ| 中位=%.2fpp 最大=%.2fpp"%(100*np.median(und),100*max(und)))
P("\n[RQ3] GLM 方差归因 (logit, 二项)")
d0=smf.glm("e~1",df,family=sm.families.Binomial()).fit(); da=smf.glm("e~C(agent)",df,family=sm.families.Binomial()).fit()
dm=smf.glm("e~C(agent)+C(model)",df,family=sm.families.Binomial()).fit(); ds=smf.glm("e~C(agent)*C(model)",df,family=sm.families.Binomial()).fit()
D0,Da,Dm,Ds=d0.deviance,da.deviance,dm.deviance,ds.deviance; tot=D0-Ds
P("  D0=%.2f  D*=%.2f  总可解释偏差=%.2f"%(D0,Ds,tot))
for nm,dD,ddf in [("Agent 主效应",D0-Da,3),("Model|Agent",Da-Dm,4),("Interaction|主效应",Dm-Ds,12)]:
  P("    %-18s ΔD=%.2f df=%d 占比=%.1f%% p=%.2e"%(nm,dD,ddf,100*dD/tot,chi2.sf(dD,ddf)))
P("\n[RQ4] 按 OWASP 类别 ASR"); ows=[]
ow={}
for o in sorted(df.owasp.unique()):
  s=df[df.owasp==o]; k=int(s.e.sum()); n=len(s); ow[o]=k/n; pe,lo,hi=wil(k,n); P("  %-4s ASR=%.1f%% [%.1f,%.1f] n=%d"%(o,pe,lo,hi,n)); ows.append((o,k,n,round(pe,2),round(lo,2),round(hi,2)))
pd.DataFrame(ows,columns=["owasp","elicited","n","asr","lo","hi"]).to_csv(OUT+"owasp_asr.csv",index=False)
P("  OWASP 跨度比=%.2fx (max %s=%.1f%%, min %s=%.1f%%)"%(max(ow.values())/min(ow.values()),max(ow,key=ow.get),100*max(ow.values()),min(ow,key=ow.get),100*min(ow.values())))
P("\n[RQ5/RQ2] 按变异算子 ASR + leave-one-out"); ops=[]
opm={}
for o in ["M1","M2","M3","M4","M5","M6"]:
  s=df[df.op==o]; k=int(s.e.sum()); n=len(s); opm[o]=k/n; pe,lo,hi=wil(k,n); rest=df[df.op!=o]; dl=100*(k/n-rest.e.mean())
  P("  %s ASR=%.1f%% [%.1f,%.1f]  Δ(LOO)=%+.2fpp"%(o,pe,lo,hi,dl)); ops.append((o,k,n,round(pe,2),round(dl,2)))
pd.DataFrame(ops,columns=["operator","elicited","n","asr","loo_delta_pp"]).to_csv(OUT+"operator_asr.csv",index=False)
ca3=df[df.op.isin(["M1","M2","M3"])]; ta=df[df.op.isin(["M4","M5","M6"])]
P("  通道维(M1-3) ASR=%.1f%%  文本维(M4-6) ASR=%.1f%%  算子跨度比=%.2fx"%(100*ca3.e.mean(),100*ta.e.mean(),max(opm.values())/min(opm.values())))
open(OUT+"analysis_report.txt","w").write("\n".join(L))
