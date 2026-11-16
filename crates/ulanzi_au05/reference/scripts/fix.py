import re,sys,struct
exec(open(sys.argv[3]).read().split('if __name__')[0])
p=sys.argv[2]; ib,S=sections(p); d=open(p,'rb').read()
def off(v):
    r=v-ib
    for n,vs,va,rs,ra in S:
        if va<=r<va+max(vs,rs): return ra+r-va
out=[];pend=None
for l in open(sys.argv[1]):
    m=re.match(r'\s+([0-9A-F]{16}): (\S+)\s*(.*)',l)
    if not m: continue
    op,arg=m.group(2),m.group(3)
    s=re.search(r'lea +\w+,\[(00000001406[0-9A-F]+)h\]',op+' '+arg)
    if s: pend=int(s.group(1),16); continue
    q=re.match(r'qword ptr \[.*\],([0-9A-F]+)h?$',arg)
    if op=='mov' and q and pend:
        n=int(q.group(1),16)
        if 0<n<80:
            o=off(pend); out.append('S:'+d[o:o+2*n].decode('utf-16-le','replace')); pend=None; continue
    q=re.match(r'dword ptr \[.*\],([0-9A-F]+)h?$',arg)
    if op=='mov' and q: out.append('I:'+str(int(q.group(1),16)))
print(' | '.join(out))
