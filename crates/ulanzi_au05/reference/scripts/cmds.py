import re,sys,bisect
lines=[]
for l in open(sys.argv[1],encoding='utf-8',errors='replace'):
    m=re.match(r'\s+([0-9A-F]{16}): (\S+)\s*(.*)',l)
    if m: lines.append((int(m.group(1),16),m.group(2),m.group(3).strip()))
addrs=[a for a,_,_ in lines]
def idx(a): return bisect.bisect_left(addrs,a)
exps={}
for l in open(sys.argv[2]):
    p=l.split()
    if len(p)==4 and re.fullmatch(r'[0-9A-F]{8}',p[2]): exps[p[3]]=0x180000000+int(p[2],16)
def func(a,maxn=1500):
    i=idx(a);out=[]
    while i<len(lines) and len(out)<maxn:
        out.append(lines[i])
        if lines[i][1]=='ret' and i+1<len(lines) and lines[i+1][1]=='int': break
        i+=1
    return out
def headers(body):
    res=[]
    for j,(a,op,arg) in enumerate(body):
        if op=='and' and arg=='al,0F1h':
            # look back for type byte
            typ=None
            for k in range(j-1,max(j-6,0),-1):
                m=re.match(r'byte ptr \[(.+)\],([0-9A-F]+)h?$',body[k][2])
                if body[k][1]=='mov' and m: typ=int(m.group(2),16);break
            grp=None;cmd=None;f3=None
            for k in range(j+1,min(j+12,len(body))):
                o,ar=body[k][1],body[k][2]
                if grp is None and o=='or' and ar.startswith('al,'): grp=int(ar[3:].rstrip('h'),16);continue
                m=re.match(r'byte ptr \[(.+)\],([0-9A-F]+)h?$',ar)
                if o=='mov' and m and cmd is None: cmd=int(m.group(2),16);continue
                if cmd is not None and o in('or','and') and ar.startswith(('al,','byte ptr')):
                    f3=(f3 or '')+o+' '+ar.split(',')[-1]+' '
                if cmd is not None and o=='mov' and m and f3 is not None: break
            res.append((hex(a),typ,grp,hex(cmd) if cmd is not None else None,f3))
    return res
skip=set()
def walk(a,depth,seen):
    if a in seen or depth<0: return []
    seen.add(a);b=func(a);r=headers(b)
    if depth>0:
        for x,op,arg in b:
            if op=='call' and re.fullmatch(r'[0-9A-F]{16}',arg):
                t=int(arg,16)
                if 0x180001000<t<0x18005F000 and t not in skip: r+=walk(t,depth-1,seen)
    return r
for name,a in sorted(exps.items()):
    if name.startswith('hid_'): continue
    r=walk(a,int(sys.argv[3]) if len(sys.argv)>3 else 3,set())
    u=[]
    for x in r:
        if x[1:] not in [y[1:] for y in u]: u.append(x)
    print(name, ' | '.join(f'type={t} grp={g} cmd={c} b3={f}' for _,t,g,c,f in u))
