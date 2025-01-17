---
title: 2025 SUCTF
published: 2025-1-15
description: '学到了很多的东西，但是感觉拖了队伍的后腿/(ㄒoㄒ)/~~'
image: ''
tags: [Crypto]
category: '比赛记录+复现'
draft: false 
---

## SU_signin

### 题面：

```python
from Crypto.Util.number import *
from secret import flag

bit_length = len(flag) * 8

p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
E = EllipticCurve(K, (0, 4))
o = 793479390729215512516507951283169066088130679960393952059283337873017453583023682367384822284289
n1, n2 = 859267, 52437899

while(1):
    G1, G2 = E.random_element(), E.random_element()
    if(G1.order() == o and G2.order() == o):
        P1, P2 = (o//n1)*G1, (o//n2)*G2
        break

cs = [(randrange(0, o) * P1 + randrange(0, o) * G2).xy() if i == "1" else (randrange(0, o) * G1 + randrange(0, o) * P2).xy() for i in bin(bytes_to_long(flag))[2:].zfill(bit_length)]
print(cs)
```



### 分析：

* 当当前比特位为"1"时，cs中是$$k_1P_1+k_2G_2$$

* 当当前比特位为"0"时，cs中是$$k_1G_1+k_2P_2$$

而且已知$$G_1,G_2$$的阶都是o，所以$$oG_1=oG_2=O$$

且$$P_1=\frac{o}{n_1}G_1,P_2=\frac{o}{n_2}G_2$$



根据这一点就知道假如我们给cs中的结果都乘上$$n_1$$

* 如果当前比特位为"1"的话，就会得到$$n_1k_2G_2$$，这是$$G_2$$的倍点，用sage中的weil_pairing双线性配对函数可以检验，因为$$e(n_1k_2G_2,G_2)=e(G_2,G_2)^{n_1k_2}=1$$

* 如果当前比特位为"0"的话，就会得到$$n_1k_1G_1+n_1k_2P_2$$



不过本题我们并不知道$$G_1,G_2$$，但是可以用cs中的任意一个点用来检验其它的点是否满足



### 题解：

```python
from Crypto.Util.number import long_to_bytes

p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
E = EllipticCurve(K, [0, 4])
o = 793479390729215512516507951283169066088130679960393952059283337873017453583023682367384822284289
n1 = 859267
n2 = 52437899

cs = [...]

pt1 = E(cs[0])*n1
pt2 = E(cs[0])*n2

ans = ""
for pt in cs[1:]:
    pt = E(pt)*n1
    if pt2.weil_pairing(pt,o) == 1:
        ans += "0"
    else:
        ans += "1"

print(ans)
ans = int(ans, 2)
print(long_to_bytes(ans))
```





## SU_rsa

### 题面：

```python
from Crypto.Util.number import *
from hashlib import sha256
flag = open("flag.txt").read()
p = getPrime(512)
q = getPrime(512)
e = getPrime(256)
n = p*q
d = inverse(e,(p-1)*(q-1))
d_m = ((d >> 512) << 512)
print("d_m = ",d_m)
print("n = ",n)
print("e = ",e)

assert flag[6:-1] == sha256(str(p).encode()).hexdigest()[:32]
# d_m =  54846367460362174332079522877510670032871200032162046677317492493462931044216323394426650814743565762481796045534803612751698364585822047676578654787832771646295054609274740117061370718708622855577527177104905114099420613343527343145928755498638387667064228376160623881856439218281811203793522182599504560128
# n =  102371500687797342407596664857291734254917985018214775746292433509077140372871717687125679767929573899320192533126974567980143105445007878861163511159294802350697707435107548927953839625147773016776671583898492755338444338394630801056367836711191009369960379855825277626760709076218114602209903833128735441623
# e =  112238903025225752449505695131644979150784442753977451850362059850426421356123
```

### 分析：

很纯粹的RSA，已知d的高512位，可以用来恢复p，这样的题在去年的强网杯的traditional game中遇到过，所以很快找到了论文

https://eprint.iacr.org/2024/1329.pdf

照着论文打了一遍发现最后一步的copper跑的特别慢一直没出结果



过程是：

* 从这个等式出发：

$$
ed=1+k(n-(p+q)+1)
$$

* 我们已知的是e和d高位以及n，所以可以求出k
  $$
  k=\lfloor\frac{ed_h}{n}\rfloor+1
  $$

* 得到k之后，将已知的$$d_h,k$$都代入等式，令$$p+q=s$$：
  $$
  e(d_h+d_l)-1-k(n+1-s)=0
  $$
  稍作整理：
  $$
  p+q=s=N+1+k^{-1}\ \ (mod\ \ e)
  $$
  我们就可以得到$$\overline{p}=p\ \ (mod\ \ e)$$通过以下方程：
  $$
  x^2-sx+N=0\ \ mod\ \ e
  $$

* 表示为$$p=te+\overline{p}$$，令$$t_0=\frac{p_0-\overline{p}}{e}$$

* 解方程
  $$
  (t_0+x)e+\overline{p}=0\ \ (mod\ \ n)
  $$



不过一直没做出来，赛后在别的师傅的提醒下发现是自己没有仔细看这篇论文导致的，照着这个论文打出来的脚本要大概跑3，4小时。。。



### 题解：

赛后复现

```python
from Crypto.Util.number import *
from gmpy2 import iroot,invert
from tqdm import *
from hashlib import sha256

dh =  54846367460362174332079522877510670032871200032162046677317492493462931044216323394426650814743565762481796045534803612751698364585822047676578654787832771646295054609274740117061370718708622855577527177104905114099420613343527343145928755498638387667064228376160623881856439218281811203793522182599504560128
n =  102371500687797342407596664857291734254917985018214775746292433509077140372871717687125679767929573899320192533126974567980143105445007878861163511159294802350697707435107548927953839625147773016776671583898492755338444338394630801056367836711191009369960379855825277626760709076218114602209903833128735441623
e =  112238903025225752449505695131644979150784442753977451850362059850426421356123

k = (e*dh)//n + 1

S = n+1-((e*dh-1)//k)
D = iroot(abs(S**2-4*n),2)[0]
ph = int((S+D)//2)

k_inv = invert(k,e)
s = (1+n+k_inv)%e

PR.<x> = PolynomialRing(Zmod(e))
f = x^2-s*x+n
res = f.roots()
print(res)

for pt in res:
    for i in tqdm(range(2^12)):
        pl = int(pt[0])
        PR.<x> = PolynomialRing(Zmod(n))
        f = (2^12*x + i)*e + pl
        f = f.monic()
        ans = f.small_roots(X=2^244,beta=0.49, epsilon=0.02)
        if ans != []:
            t = int(ans[0])
            p = e*(2^12*t + i) + pl
            q = n//p
            if p*q == n and isPrime(p) and isPrime(q):
                print(sha256(str(p).encode()).hexdigest()[:32])
                print(sha256(str(q).encode()).hexdigest()[:32])
                print(i)
```

![image-20250115100211992](https://a1ic3-blog.oss-cn-hangzhou.aliyuncs.com/img/image-20250115100211992.png)

也要至少二十分钟。。。



### 学习：

后来看到了小鸡块师傅的wp，他第一步使用格规约，然后是用多线程加速了最后的copper

```python
from Crypto.Util.number import *

d_m =  54846367460362174332079522877510670032871200032162046677317492493462931044216323394426650814743565762481796045534803612751698364585822047676578654787832771646295054609274740117061370718708622855577527177104905114099420613343527343145928755498638387667064228376160623881856439218281811203793522182599504560128
n =  102371500687797342407596664857291734254917985018214775746292433509077140372871717687125679767929573899320192533126974567980143105445007878861163511159294802350697707435107548927953839625147773016776671583898492755338444338394630801056367836711191009369960379855825277626760709076218114602209903833128735441623
e =  112238903025225752449505695131644979150784442753977451850362059850426421356123

k = e*d_m // n + 1
L = Matrix(ZZ, [
    [1, 0, 0, e],
    [0, 1, 0, k],
    [0, 0, 2^512, e*d_m - k - 1 - k*n],
])
L[:, -1:] *= 2^1000
L = L.LLL()
res = L[1]
t = res[1] % e

PR.<x> = PolynomialRing(Zmod(e))
f = x^2 + n - t*x
res = f.roots()
pl = int(res[0][0])

import multiprocessing
import tqdm
from hashlib import sha256

def copper_attack(i):
    PR.<x> = PolynomialRing(Zmod(n))
    f = e*(2^12*x + i) + pl
    f = f.monic()
    res = f.small_roots(X=2^244, beta=0.499, epsilon=0.02)
    if(res != []):
        t = int(res[0])
        p = e*(2^12*t + i) + pl
        q = n // p
        assert p * q == n and isPrime(p) and isPrime(q)
        print(sha256(str(p).encode()).hexdigest()[:32])
        print(sha256(str(q).encode()).hexdigest()[:32])
        return True

with multiprocessing.Pool(processes=16) as pool:
    for _ in tqdm.tqdm(pool.imap(copper_attack, range(2^12)), total=int(2^12)):
        if(_):
            break
```

效率大概是我的十倍了

![image-20250115101147421](https://a1ic3-blog.oss-cn-hangzhou.aliyuncs.com/img/image-20250115101147421.png)



官方wp如下：

```python
import itertools
from sage.rings.polynomial.multi_polynomial_sequence import PolynomialSequence
from tqdm import *

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def small_roots(f, X, beta=1.0, m=None):
    N = f.parent().characteristic()
    delta = f.degree()
    if m is None:
        epsilon = RR(beta^2/f.degree() - log(2*X, N))
        m = max(beta**2/(delta * epsilon), 7*beta/delta).ceil()
    t = int((delta*m*(1/beta - 1)).floor())
    f = f.monic().change_ring(ZZ)
    P,(x,) = f.parent().objgens()
    g = [x**j * N**(m-i) * f**i for i in range(m) for j in range(delta)]

    g.extend([x**i * f**m for i in range(t)])
    B = Matrix(ZZ, len(g), delta*m + max(delta,t))
    for i in range(B.nrows()):
        for j in range(g[i].degree()+1):
            B[i,j] = g[i][j]*X**j
    B = flatter(B)
    f = sum([ZZ(B[0,i]//X**i)*x**i for i in range(B.ncols())])
    roots = set([f.base_ring()(r) for r,m in f.roots() if abs(r) <=
    X])
    return [root for root in roots if N.gcd(ZZ(f(root))) >= N**beta]
d_m =  54846367460362174332079522877510670032871200032162046677317492493462931044216323394426650814743565762481796045534803612751698364585822047676578654787832771646295054609274740117061370718708622855577527177104905114099420613343527343145928755498638387667064228376160623881856439218281811203793522182599504560128
n =  102371500687797342407596664857291734254917985018214775746292433509077140372871717687125679767929573899320192533126974567980143105445007878861163511159294802350697707435107548927953839625147773016776671583898492755338444338394630801056367836711191009369960379855825277626760709076218114602209903833128735441623
e =  112238903025225752449505695131644979150784442753977451850362059850426421356123
k = (e*d_m-1)//n + 1
s = (n+1+inverse_mod(k, e))%e
PR.<x> = PolynomialRing(Zmod(e))
f = x^2-s*x+n
p0 = int(f.roots()[0][0])
PR.<x0> = PolynomialRing(Zmod(n))
for i in tqdm(range(0, 2**6)):
    f = e*(x0+2**250*i)+p0
    root = small_roots(f, X=2**250, beta=0.48, m=25)
    print(root)
x0 = 769306974883685623850311905036778346829296744303179040979107875413852719182
p = e*(x0+2**250*44)+p0
q = n//p
print(p, q)
```

用flatter加速，效率跟小鸡块师傅的差不多







## SU_mathgame

### 题面：

```python
import socketserver
import signal
from Crypto.Util.number import *
from random import randint
import time
from sage.geometry.hyperbolic_space.hyperbolic_isometry import moebius_transform
from secret import flag

banner = br'''
 _____ ______   ________  _________  ___  ___          ________  ________  _____ ______   _______      
|\   _ \  _   \|\   __  \|\___   ___\\  \|\  \        |\   ____\|\   __  \|\   _ \  _   \|\  ___ \     
\ \  \\\__\ \  \ \  \|\  \|___ \  \_\ \  \\\  \       \ \  \___|\ \  \|\  \ \  \\\__\ \  \ \   __/|    
 \ \  \\|__| \  \ \   __  \   \ \  \ \ \   __  \       \ \  \  __\ \   __  \ \  \\|__| \  \ \  \_|/__  
  \ \  \    \ \  \ \  \ \  \   \ \  \ \ \  \ \  \       \ \  \|\  \ \  \ \  \ \  \    \ \  \ \  \_|\ \ 
   \ \__\    \ \__\ \__\ \__\   \ \__\ \ \__\ \__\       \ \_______\ \__\ \__\ \__\    \ \__\ \_______\
    \|__|     \|__|\|__|\|__|    \|__|  \|__|\|__|        \|_______|\|__|\|__|\|__|     \|__|\|_______|

'''
welcome = b"\nWelcome to my math game, let's start now!\n"


class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        try:
            if newline:
                msg += b'\n'
            self.request.sendall(msg)
        except:
            pass

    def recv(self, prompt=b'SERVER <INPUT>: '):
        self.send(prompt, newline=False)
        return self._recvall()

    def game1(self):
        self.send(b"\nLet's play the game1!")
        rounds = 1000
        pseudo_prime = int(self.recv(prompt=b'[+] Plz Tell Me your number: '))
        if isPrime(pseudo_prime):
            self.send(b"\nNo! it's a prime, go away!")
            self.request.close()
        for i in range(rounds):
            if pow(randint(2, pseudo_prime), pseudo_prime - 1, pseudo_prime) != 1:
                self.send(b"\nYou failed in round " + str(i + 1).encode() + b', bye~~')
                self.request.close()
        self.send(b"\nCongratulations, you have won the game1!\n")
        return True

    def game2(self):
        self.send(b"Let's play the game2!")
        res = self.recv(prompt=b'[+] Plz give Me your a, b, c: ')
        a,b,c = [int(x) for x in res.split(b',')]
        try:
            assert (isinstance(a, int) and isinstance(a, int) and isinstance(c, int))
            assert a > 0
            assert b > 0
            assert c > 0
            assert a / (b + c) + b / (a + c) + c / (a + b) == 4
            assert int(a).bit_length() > 900 and int(a).bit_length() < 1000
            assert int(b).bit_length() > 900 and int(b).bit_length() < 1000
            assert int(c).bit_length() > 900 and int(c).bit_length() < 1000
            self.send(b"\nCongratulations, you have won the game2!\n")
            return True
        except:
            self.send(b"\nNo! Game over!")
            self.request.close()

    def final_game(self):
        self.send(b"Let's play the game3!")
        set_random_seed(int(time.time()))
        C = ComplexField(999)
        M = random_matrix(CC, 2, 2)
        Trans = lambda z: moebius_transform(M, z)
        out = []
        for _ in range(3):
            x = C.random_element()
            out.append((x,Trans(x)))
        out = str(out).encode()
        self.send(out)
        kx = C.random_element()
        kx_str = str(kx).encode()
        self.send(kx_str)
        C2 = ComplexField(50)
        ans = C(self.recv(prompt=b'[+] Plz Tell Me your answer: ').decode())
        if C2(ans) == C2(Trans(kx)):
            self.send(b"\nCongratulations, you have won the game3!")
            self.send(flag)
            self.request.close()
        else:
            self.send(b"\nNo! Game over!")
            self.request.close()

    def handle(self):
        signal.alarm(300)
        self.send(banner)
        self.send(welcome)
        step1 = self.game1()
        if not step1:
            self.request.close()
        step2 = self.game2()
        if not step2:
            self.request.close()
        self.final_game()


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10001
    print("HOST:POST " + HOST+":" + str(PORT))
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
```

### 分析：

#### game1：

要求找到一个伪素数，也就是一个卡迈克尔数，要通过1000次费马素性检测，也就是对任意选取的a要满足
$$
a^{n-1}=1\ \ (mod\ \ n)
$$
![image-20250115140129412](https://a1ic3-blog.oss-cn-hangzhou.aliyuncs.com/img/image-20250115140129412.png)

```python
while True:
     k = getrandbits(100)
     a = 6*k+1
     b = 12*k+1
     c = 18*k+1
     if isPrime(a) and isPrime(b) and isPrime(c):
         n = a*b*c
         print(n)
         break
```



#### game2：

非常经典的问题，求满足
$$
\frac{a}{b+c}+\frac{b}{a+c}+\frac{c}{a+b}=4
$$
的解



参考Tover师傅的[🍎🍌🍍 | Tover's Blog](https://tover.xyz/p/cubic/)

只要在其中的代码基础上加个900<bits<1000的检验即可

```python
# sage
def solve(n, N=3, check=True):  # count N groups
  R.<x, y, z> = QQ[]
  f = x^3+y^3+z^3-(n-1)*x^2*(y+z)-(n-1)*y^2*(x+z)-(n-1)*z^2*(x+y)-(2*n-3)*x*y*z
  tran = EllipticCurve_from_cubic(f, None, True)
  tran_inv = tran.inverse()
  EC = tran.codomain()
  g = EC.gens()[0]
  P = g

  count = 0
  while count<3:
    Pinv = tran_inv(P)
    _x = Pinv[0].numerator()
    _y = Pinv[1].numerator()
    _z = Pinv[0].denominator()
    if _x>0 and _y>0:
        if(int(_x).bit_length() > 900 and int(_x).bit_length() < 1000 and \
        int(_y).bit_length() > 900 and int(_y).bit_length() < 1000 and \
        int(_z).bit_length() > 900 and int(_z).bit_length() < 1000):
            print(_x, _y, _z)
            break
    P = P+g

solve(4)
```



#### game3：

考的是莫比乌斯复交比不变性

比赛的时候没有想出来怎么做，泯了



赛后看了S1uM4i的wp

```python
from Crypto.Util.number import *
from sage.geometry.hyperbolic_space.hyperbolic_isometry import moebius_transform

C = ComplexField(999)
M = random_matrix(CC, 2, 2)
Trans = lambda z: moebius_transform(M, z)
out=[(0.244112983961970192357276289991059882588620721015403423815514432642156521515111102444559393022381302355136158413254449970198185892698333791554526819270236087449499827576129424297460024027743142236525135502689025584933796561604937969098816786387407398078718976334076866904249305446092438933350008787853 - 0.233400166352224109274410058325662894326563909546315758541911715437482257571741923072753825198082523063899481560749263145013410197180074049215374847252575160248916989695238410326711084190392738035555658193249942813984317199598925753434338878105637820155065352223070457728690440164073975917319977615942*I, -0.502697404559782 - 0.339037837578924*I), (0.802867823110887314343945708942091256601620959031911555393799526189607680197869377058120796290446480177693628543697146383459525816680810080641295153893040669795406681701307727202810824292802921270405325000789118184596919161352127397136441946528498717570855840470237410361793615926150523470313497920493 - 0.310600733486570889134246708003853818331642769136614548629569027678304032854885038238973196838185860910877059395740916762683702976158674744020852398470166772148710499283072430336687456097056603056580225447500067137544153869956033916942354952716412455465043340142422526784030271354240365080703262226656*I, -2.51316139420834 + 3.12575747766860*I), (0.519311726970731102981320783513557095465156406190605731070614431985721726459108582756088242933539700259596737208933629183429452670170315074027848183653766950217648145476941084339184217026729407806772699856919763123067740212978049947133058263170549386630813860362176551808477984127116687155390851785093 + 0.152933313892859167495031518929538793251604273728408742559231469751257221329963901558174591430417895760497965752617230591751437997181680378559206647608605856269956794365891641694896581193297096915066485494072512124859878150484199585116155696321828963695306584681144643593099555661189964535226333795783*I, -0.846778208409024 - 0.966243647110718*I)]
kx=0.314839297104703726560968455665739547158434538825624735980654522237164690181390247612268591459438551516155528322244515612475075838547116857381573566324052221159594846542470454630282487660589908643210426837761699859434679217871419017698762187896761042619478975901161671608901416669392489830352975746254 + 0.913310488636953809158606180318266676132493037615495257483187554288159163788866285462847483089354074422891427993783077203828482060391429592768341251418159183429474336928732255522710552067666053383226956897886566771773722698848288260215985569034790548222156838013975910121516415588011227036114606307969*I
C2 = ComplexField(50)

Z, W = [], []
for z,w in out:
    Z.append(CC(z))
    W.append(CC(w))

print(len(Z))

z=CC(kx)
A = (W[0] - W[1]) * (z - Z[1]) * (Z[0] - Z[2])
B = (W[0] - W[2]) * (Z[0] - Z[1]) * (z - Z[2])
fz = (A * W[2] - B * W[1])/(A - B)

print(CC(fz))
```

原理之后学（逃



## SU_Poly

### 题面：

```python
from Crypto.Util.number import *
from hashlib import md5
from secret import flag
import signal

PR.<x> = PolynomialRing(Zmod(0xfffffffffffffffffffffffffffffffe))
SUPOLY = PR.random_element(10)
gift = []
for i in range(bytes_to_long(b"SU")):
    f = PR.random_element(10)
    gift.append([int((f*SUPOLY)(j)) & 0xff for j in range(10)])
print("🎁 :", gift)

signal.alarm(10)
if(md5(str(SUPOLY.list()).encode()).hexdigest() == input("Show me :)")):
    print("🚩 :", flag)
else:
    print("🏳️ :", "flag")
```

之后填坑吧。。。