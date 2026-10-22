#!/usr/bin/env python3
"""NodePilot: unofficial host administration companion with a read-only live TUI and browse-only web UI.

The curses interface executes only a fixed allowlist of documented read-only
``hvmcli`` argv.  The web interface remains catalog/preview-only and has no
execution endpoint.
"""
from __future__ import annotations

import argparse
import base64
import curses
import hmac
import json
import os
import queue
import re
import secrets
import selectors
import shlex
import subprocess
import sys
import textwrap
import threading
import time
import urllib.parse
import webbrowser
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import NamedTuple

VERSION = "0.2.0"
CATALOG_BUILD = "hvmcli 1.0.0 (build 20260930)"
SAFETY = "READ-ONLY LIVE TUI | WEB HELP/PREVIEW ONLY"
_CATALOG_B85 = "c-rkf`*Yhilm7}Pzr>zOvYkgCuFrF++qAxG5?`FAcb9nbQ6wetLXiv~cGT1Nzu!Ip5PX27Y&o6wq-kS`02hnJVt27vEZ+U^gT%=f4~`!!u9t2Y2sbRU+)qUmdw%v{^q|O`xo;^J<8c^dxp+4o|4$Z2S5SQxI`izo@w*572%d1A2Unv93qMQ%(r*aySPTOA&yfwkEO+vv1HltFUM`);I~DKZBoE>!tD)!l(_&8e5niK>F>Yz$ee^#1(a+p8pa;j|auMHDQ1-FPvuh^^ooVO`2_idw9|_qdA;gbCmW0l#)>i=)#it@pi=_ynS)48%Yy{tA;=$)vq+XSzH$lEIA*3<1yT^Up$Ct5__%0($zW{g%#aa4U;<$wQ&tW`uLLvK0STos#{=6#kq{sn7@o$%}UJAyOD-y|d#h)S~!L^@G<IERa7{>E?5Y0s%1J0hGru?SHu|zaq1Q}u5!X%!bgz-uMX<^{fCX-al#ryZ-9aCtXq`tfG-H&TPBwHi+t8#cPjP7{LAQ~r5mfgguHwL@|W+N^rGC~1<CP^4Lk?W6(G^8g}$Ne}@<0A6trx!T$D9-Z0&G>i3f9JqAH_nQg70Pi)=tr=`Zqc_0#%czm#J?K+9Qh0?^7EyWedO=)I7#ErEA<07BSeh&cg`@%8kz5;?qcl4OGoxE3;y8tu0tmp2cC7xH0X_^+C_3%qd|C{U<Aw&Z(sZ*UPzGFL7Er9nM=oAKxZdd@v@kX+b5W2B1UZKN4YG-Y6>B$_PU7h!FU!1^99T;EXYJ0g)6LzC|B81b`=VEk^$kx$;;D`s0?p);x&01(SPlKDuUGa1hJZ&Ye6DTg5*@Re%`(i=NH29ywuM!t}n-1oZ!Fp*IxQLaO_7xHTL|;e1gEo62R%coO_bv#0ma;+GtXhO9YW6#YvF{ElB>y*{k0l39j<n>vOR;3qt?+;6Q-9S>$=Lm+iwZ*{)`3Knnj<;Nf^*f@pIWB%s9JuR&CN7SlBF=KemyD_`FW{kh|=#H+WL5_CB+0aN(50{R&i3VdAls%?tv7he00C#Z%{HN-59mx8L{P`)BQ2KF?EQqJo3@%&j9o?l4O837vsN+2z>M(rP8UJ6+z_K4$QvL;RnFg)4g%H$O%{P(o-K2{L2!d~hpzLS%HMqN;aIRcLPES^fxASo1T&3?Rmb0JY11oIm;K&GffZVC<1&r~7s(63_8^Jh*G=EuZA8SoDhRCOC9lsLIuzgYiz+BRLNyoB&VzD7c?-mLok@&@|EHK2V-gIK+TYPI&#OI3(vTwe-I7<;eTg65XDzdn2UJ<ugbnKnn3%%s3Wi8T^lFq`=)3NI=;i<h8zeT|Wl=gltsyYDC1ebC!8Fhz<Kh>(2**`i*NbSU*xi?l(>2&`h%S%SgQW)jpsWEaF_CiLoVlCV1kzEj{k1-?_@I|aT|;5!BW7gOL$81Iz$PKoc7_)dxMl=x1G@09poOo`ieTXrgZr^0tCe5b;9DtxEHcPji(RN*)|-k{Kf|MG=jZsY%>Rg?c?ByJV~uqn!4k%7p}gj=LU0z;GowdW|oz83*JkAXB%Oaea5L2X37DfcIKD*|O>$2L3{-=Fc21Rwp?-_lIL?@Yb1>Z1IKhEb0Zp~=2A8{&6{xHBQ(BWdv`SQ2H+e?fzyWZxF8p=?ytRw(2o2fJ|;`ECw^FRlQADIreapVKz-r2ZU~NJ=480xBtW8MMDe&Btl7@PTQcU7Q=Q^jb795<7EdJLb&J4Ed{i669R%+|J(_0y{%sX9(;Jft?|+GX!>qz~9>t=nV_l83Q|GU}p^MjDejourmgB#=zg(80ZNv*qH)5Q($Kb>`Z~3DX=pIcBa7JJ5Hfu5qzOAg@u!PHxAHb8pru{92TU_Yqm&BC2``oIC7_588B>0b`ZR3wg@g|F+h1Tv@S{k#sLBn5)x*5z=1+G@&Zs5o}UAltRvwA=`*0&+|Rpc<R(Q2aiDZNRA~h?lpJRlzX_B|K@MUcn0*A2KZ!xjuSP@}X@CTOuyo%VZGvPObPxxNw?mzFNJGi<!;7<n^NSbfs2FpU05IW@EFgWhM~kJujMG&IHMqid=wX93lp^wdBtmxMB*JwP#|`q;_Q;XAU7P`>+aW|NprKT_I6DUce+^O+i9wb~m;uDw_uhBHd?753UbFO8oo;>Kip348RVx-$icrY-yar_qrU}dsFFUm@C{@jJY1f14ur`_<(Draf1J>+Atpcr-$78V2DNoVdkNngL*B;nV>&%PR5w9WEK4{<+eynG%wUZ2_zl%*2Xic~=7W%yb#JHYylHz*C*4f%k!F=@Bo*(+~CxfQ23+<Vq2J~+@T%34k=Au^3H=0D3ugB-F-X6StuGYFZp&W7X9BVRc0XAMV3+8CBMa6Oogp6n6?Q>kz>Z;s6SmXTH2}2a@{FYa*3|P`MF5yD^PM)X16imsikKhuoKDtZnfe$N-L0*iGVWD4u*>-X`K6>=6P2N$R7FWtpE;O-dtV$UXRZvA|GY*v0?<0sDqjrLHh?m=RTesEO?ZF-F6*;obm+71#T<+dAm<)YA!}(%kV-y6qo`d$5j*I>pDMxX&hy3*9@Vh7c<WrmxgB`+$pJYiK&)mgFaS})CcsApwd0IgKDvu~_94Pf7kJmosOk0CRkAJ&0Q<b{-1@NQ4fDF3}B?|l_=Xou0U^n7SdlLr^50k5BzA3ut(K4u~pVernpVug<pSRFcm({6SzSKqAUS=YPqRf-m<Ri0GYUD7u_G?3hkF2z<fsp7h6bm{_>4O>roG7<oRjqUv<QkBM;E0I{Etp}^UGS0b_h2DS4~u9sOK)SBw!d%30@Q8?7FbF=Oh&diL7(mE)nqd1OS>tp@;)pFz;8hv$&CJmB5A?AEVL!xbXdM<-DxD@45BQ7ReMW9PW&P_lt^HK;qMipuccSPQmu$|iM8)-7?%E4<!I%`#0mDDy>@3X6=78*3-GyI1!-{PcDR;aF}=LfA4<^ae};e2GsEv>N?cOMK^ifLQ@J#CqF{z&1csl}+KSZohO1v$f&w81v%qbAPmxKy^I&bbx&pIQJ)s8z#Udsdb*qRvfa5Q}9KU#>J(+KUrB8%VAU)M!>1sVZJU%>>ZpLzmN<a8AzV;jMOGM4BpmGr^o6w+e^)5Ro$fUEmCM*8PW_r;<DMpEfw3%(01iBnW+DVirYcI;yYS(2=PU3YKyAJ4`kN#@uB<mbV`9~c2xW6_AlESLq16Hx7v2{GJo6Sueu(x+aqqf&a{#=qAJZaFUFRF(?y@Qkow{+=eVh^46j|HrO3oslKT-U%q<c=dA!EFm09CO!#JT~SIga$2ZjKot_!uxn?XH1VY2tEC9&;RVWIj}x-owjZ~Msc6F8que3eDoShVU_?#;s#ln`v%|eBQJ@;7$Rh2<?DyVi3ch(aM-(4rL*445^1)|aDUP$+e1hAs2o__7a*Huzn4!1?_hWHD$<@+F!ui>NY=AYUUZ5oVGTr)eKnu6o!Yunq)Pd%o=UB|_Fh#LFd*Y=+dg>Z$-wEs-IkWa@Sc~pq`hmpPCpfTjm{d@M)*PZsA?Xk)eQAdJvtpi`+-z6no--Im6kT`AIqcO-f=bV8?Hf4_`zwPk(6~=NR}ql#;DQCroCce+uJLyhP~R84f2!I3OmYY`+a>iX3hrP);M4f2cc0VM$@dSKp>-to5*AGO<%*3Y$PbM!H+)tb~*X&&GYfMBQZ-qJbx{Jyl>xZ1PkPhYap-`tfm-xfYuo-L&>Qv%@IbVhPjDI5rM+UoiLo>E-P*vW@s^pAV>cuD2E`j;BesQ?g2xbz?z72uKVK@Y#vF=F+84#Hw$*fvo+T80l}a9OGSSKLuO_XggMxX@_8oCMyk&iIQZtptIPBM6s{BD#^@BZ3iaHZSS+NUmO-wfbAU>Y$9wO32lr(Rs|I5<u?bDivK2R8P62|4yT&om>>7|pR-lHTxvrn&7&8;6OHk#=Y)&*UfEnL?c=OZi*XM6uz5cJOcM}&A+57p`yMJBA9+<O!dZp-raJX}nr{17O+3yMNTw}$Dog9wF`dCu+Atj*qeQ~n@YnSZ6NbYrKMUup6p7Bm%1tjX_F~ijWay`tloykz?P(f%XDt4k`Cn|QLqKS~XY#1OVDys}!l_Dl<T|>D)>pNK%fdRzMgNVk7gazOBQ8n0+1S)bhkKH&NE>3F5((<(v->yj1XU4ua0<nfG@ue*?%!rqAp1J-qI!!xu8sQ2(1g;v4Z8oFmKvCiVX>(9sks>?Oj@FN|umvL)96Y6{LG14)w5>Y{sy!j|eI1x~uIhov-DF*OiLr3OK8d68*H525eri1CUW#<)K7I1&$r}DXKKlB})h$ftcFZ^B{fckK*5B5iHu~7nyFY*0{B?&`&W23~R!ySYc<wg?ylIC}>TKE@l2lvoN)>8vKltoHH{R&^W9zfxJ83vmu58|v(mztIyuYDmXdp!xUumgs9pyg5w%VX{aDp5+oTT3ij(ZkGf)>JKfj(LGm6p~~)jBN!N`Lxo0XBW+!|l9hOzEYw5(@`$fcHSih;J$mU?V~WOujq@19~EUn-)=C@F|0g^>mQ%4Q8{rNJSEZSkkWF5YbrSfsc%$qq7)yJV17RWDFJ##u%qyS<T=d0vE=42F+xCNi?7Y7UQc>3RWB#;%JG50rnWIIcNoU7zP+)>S#{)L}8~ePZc`GfX63}4-QZgzdJ?|dqs?;5+}-y9o9RQQv_EAQ}!<DS`I!Lt2~uRRW&+v7OBq2d9=;`Y^pufmPPLXsEUTSP(9kFztCvLSj?6!4eOte;h47NKNs>&w>-PVWKDxO#qiaW5UPay5Z0-=rak-jvjCGn5>B{NsOsfGSbr#Q>AUK`>rowSQ#i<jX^{*@K`i7KXokZ}7<M;Z@6uJ}puc@@n*v;8VH`gC94w2a!j!xUd67nX4^%uo)W=P#NW;rPL@&$T9#!F3_)9;X!vZq&QxI`3JRAu>O>J%s0UAC64L`yo5P|ED=&HyO->#@OUo~;`=4+Oxftw@F$gu2A@X)i7t7A1)(!nB$PFKV;K4%p~UVNj#R|$$2J$h{w)y0qH=R9)50>(N8wStb5%+E43QYA%kl`|{CPypmiX^7kCsy7lhSZ$+Qfls2SPO~u!Yj)hv_CGtzB=l*_-#-{1E#5yE;g`pU%OK+KdF(kW{<`upP=|l=8;=ejeLX(>c6|6m9DZ~B^zrfIM_jcmc%up?PrrV0^zC>5{r-W{r^lMln3EV$Ql_cz^6FF`6=D)i#P6sp<#++tfZcbaI7Pvt4NY{tAhgt<q2G(o%7hNa8RZKuf;K)C*dvcb+4staf**NO6AcP<a44;b+vQG@_>oq!%niU-Q#vqI@_<#HT4Hik(XDOa-e??EY0R5CSqBoT%AJsD0_j4k+YfA3xf@aqAYDi)W!8z7u5>rVTEJLPOMN^EWkHDx<*L=SDl{q_xcO-X+0+_T0fZ+Wy~DXc)`Gmq7j3C!l1pa}fee;Q-wR+?hAVq#$#ZS(E&H`Gx`;xVbZn9BR^)Vr{%7Tta2vr{D*8%m{3vk8yhDo?4*S^p=+%o<lX9|Z8H!c;Two*?N|{QS6P_I9W7+yJE8{0lvZGP<Xaq|&6WD8sn2ws#_38ZKo(!2o^~%~}g!Q3+BdA!QzLxDsDt7r7lhBFK-|d35oy%*Qao2#{)+<`0Qxg@wu>nMOs<0CB5FUhAq?UA%XFt_Ba~?Ty5{KT=zeN7c(Fndh!f%gG#mn<EKA#O$62yltg-+uvqtoST6bBst91?G3kG<m4_1q0uDfsEJ+U|H?JUaUBktjz+J&~iLf6BqJO(DY<Z<$6$jav(`Rv1={iX3!gWJQOIDQq*K6;*t*{t8SIJi@W&*gO(L@SOg-nB_gBuhMt|3(fzWTO-K%g<AMHzbUg*+;EU-(6?5+7i63Afk8`)6HoDzMG{l<0^2_p521mFBk}O76WRDF`~s$aNH{z+VimtSQb*Kl+XR;inkkyuK@r7bo?@_j;)C(-$&)426(eGde>*riuY<VA@L02sc~qq0cdLDe9<gOFrfKYWu9K0uj`yYe-dNtV&~|($i)T3<4Qw~8D#f>9ZVP}8M2f^~JwjBgK)X|P&MMB<GW!S!1>Bomt7GeBIuaRrH*ntylUI~yi+Izm%IxuMhURjAw>7e~J9SHZJNK=+Pj1SX;vxa=<Asg{T~CjqlB3A1C{wolUtOvm?BP_<^|=GIH+dcSHz@95YH$o?Y@|_<hwN!xX22?w1dK$5%A`gxE?+7Hnt__!f`>+&OySMYpZtM46ZnSbq<~WZlXkzB9EP+-*|N$7K(U@o{qmGNFPf@Rnv_96*2I^LBnrR5LZz|fQg7>cRU)%|NTvvXmH6mtSuKkUVI(W5<&-7XxXx=5+x{7(2*BPRdCW~ZPGmBQtN!D61A+kU4NKpP(YAi3F=#r=dxond>ZGX&xG7A-p$|+-Nbr9efUQ*u`lCZiA95@nE7wfmRTBi^@ozDu<P*T?=ReXkDWU+D#yFd1!RP(&h0IbzK9Ag4CQuLk(^*XEEC!5dk8Cz--AP2Z!s*8@&iZkSRm^a?1~O(n{qCCM@3hf;RR!XNA=phtlm&Azm#?g0!j)=#xWrt_D0yG5X|^W$<E*k1ig=eSZjwMh-3}po{l|4g<wWWqOEu$A0n6AXsizdi*w8qS$DThu?NhNEv1Zvcsncrf%8}lJLsNvbt4#@zy^Z{pJRV{KV1zTvIrq#Q46QbKom7SUKzXg+l8ygA7=R%}u_gev)ie?SUUf^FPKQqG#2-wa5*H&Y-qofOU{fMlGbHY4rJFOdCH4?Wn|Q3T>f%_f%{~}%`N}Ss2|uCy_2dbWZl|nt1x>^=@e$Kpgk$pf;6hHLK@J-s(KtX;cZ{YkTE@@MFD}P^M6G#3I$k7jv`iJQ>TSU|gU#;9{!BU?d`+!*Yb|Kd)S~6u$*QYs;#%25iuOBG`h9dKQtQ`SXiaf<gH{bKhO71(lB%I_(wn#lJ&MA`EKPhWvUC+X<n)pr#G0e9=@Vr4vOL);dmt|30$-r*9z`Td{NvbI%g_L(=e3I&_i(KDWqK1H8{JyXfB1?|)@FHHQ06X=orinPao!&w5{61mxt!dBX<diZf}?a!&fFHfbQ#AckT+pGUcy=>pu@(!yYKRtw0^^mxY<;BTDj6%Ul5adyqTO3&x0wD;%tGg?NI#k!!tqKgVLX+;i{xt`hf?0<N7+(M#Px*u>#E85-s23jDX~ve||>E3*lwlQ={!iwORSF)@9@U(#e4V*t8o5%S9iWht*u_L>b~g=@`WzbF;uckW`FgX#^~DwxG7b?QvS&WtbHrm4M|AT)G@mm5fGZybDDryEJs@%LwB+1$K$x^6c_l<_OEod_{boV~(QC2w*m=W5^{zT%jC|Q!g99gt!Es!c$}<1}5VOZpnuPqnH1v)}P0MU2)KsiY#IfIwm3u5;ImSh=M$D;Jq<NYz3d9j$|`t-DVK86At9gW~6cpa)z<khGM_fSZUIhys52L7ri<I?>3=9Eq7BF0s4Aq@hKUlw^Dem@7u8`MU)j4Q|gEl={di4!T>dDdDLSpy>^u+IA7OvBm{3dUJZ2r59(oE7;Xi#!E&{c^THykC;<XyF~XM=YGuY_^`Lw)anj6BN5XSJ-bVZ`A5g-*;Oig@ra>6wtBP<}Jrv?+O5>ONs^JQuWGxllOBNs6g#Jw(8Y0g@&m&?b+6IssK$a?RZ4hxgo<7^sdVU9#PZBySj^*O|C1T~9G#Iti67nRW?KP>L!q_p&ydgZ#tqtLPMr$kFS_3r%&BiznLAl8sD(z(Cl{zvLClqidqb-5;#xodJSQo6ud=Bqq<!9?CRsq5JVvHL{7;*sOFAUsO1p-ybKuY2vP0XLk-((>yD)2o^eob@z-gYXdvNW!AqNdeakSq%nN>cb&G15WSH7aZ{zHM~Zxi&4N*EPBapgic)ISkcmt%G448L|&a$J*bxKY~Sy3ZSa>Fk3pQT+_C7ZKc-5tsNpb)55HxJM;blo-+VB#E}Ju7?sHyxz?Yjh~*Fd!hxl4N?86b*XO!lDpw1hCXg})%so2&3!{9XyHkFf;0qJ3iy(3D_F?yoe`p?xu1d_w#zFu)zNri#p-nc@H4Fjr1OGkc{Q6#jxvk`v)4R`g%)pQ3sh_9S*D%V792pH*<c`E-v}QpX#FYmsmoj`o?*-JBUnF$jLB|A48}*H!qZTtV-E1syB+~ptLgwJR8a|fHXcc;t(nxlBW4Q%XQKt`a!0P8kcxZ1awIrvgFz_m~Xw$dBGWQ^zEKF1i)CMb6p*I-HI7Ml)m44jCTxF|mEM_D%L`JKn6dEQ>^({4f<crfOwf2wO$HK5a<$%f>bn(nc{BrTrNc{No*+{(n>CLl?i+$VB)xoG563*j`XRk-%?AK?ngW%Q6{mRWJl3g-C$CP<W4_H_LTEZd2b^Az3_Yqb5FkOAXF)4q6d=H$k{Eg9SAIjTsY}_LR<7`t9tt>^IN6bdzQ{fl>NL_P-S;CISUmr^CR%5r4{yN+Y;}xO;@CM@=cZ8{{1~dbC&7ATJfdh6L;gN`pdUH7PfFE#wbmTAH4{qqB0g!#PNIqmYqttWUk?RIo_5ofikFMar25~(M7iKuv@c?E7xI3db%AJHkFtml2jk3gj{DF#{$QfZOa5ql<QQ)h<(B|}z%_yQD34C1<yJe<`dVM1JhhPQ+`~m60=PO=dq6lIp6%DfA5{gQPGR+0aiX1id<w#qm$BIvCz>-EENYvA?oJi_4XB889RZs(tJ^EP2v=EGG7#n*Da?g8^q0oMexxL<YmNb3Gm2GadL0I12_umU^2&QVyJ_J|2zTXPAO=xy}VP?5bWXF-q<qD8oS!^u1jV)5OXyG?9F^vHg_S51z`#C6+9AkHR!JU=();2O{oXc7{;0N|z<EgxejB2TRUE7A^9q?|FHII|_i*#gxd2vE{TJ{dtGYo*+jwN0m)Q%=yD|8=t_5p53bTM_>@q~hVL9++01<Sb2DXU8E2hSeB?TFg0?<vdf1=)Vk?dZxwAno|7RM+=`@Br9NjPd@djITfhBOI*E`LZ=xdwV^($kt_J^QK2kcJIt)fjiDu2|T@CuFJq#x_o6E&9XH{V2_u<oP!b8BnI(TmQ$5_zY-se7g?$sCVBC#uBhY?*tPt<b^}i?ll3Kq^BaD!%nNY>|Hxl{?hrD#dDgyG)*&^}I%f@2t>S)rsxRCGODT$@@!J<d_FQ1kvx#x*9%XTm^{2SqD9`;qd`PbsV5;IViivm=B*%1ewRXv1oveKE=0io!QI(tz_xbcUULXk!!I}V*#UWl8gTfik<n0I@0XpVAv-K-vD-`4>dC|C1*2J0@?p3y_+!kx&b1NIlRbx9Rs^UBHW934KmYDG>Z<Z_jZVuJ;s(f1BNKtZY`K-#b{R{3d&%k)L{m<awP7!CjGN@6dPp}aKse7ah78#F=Bn+aDYA1Mh^llW)9?7&LT!dFu^37<_Pd*O0{`T<E<gw$GceWTpZ!3ay8*;OXm%5mNZ_Aav3h@G6`Dh(qXWBtZ@3LBg#htuOCMm<oeUGZZ@;SvAGWniEG~)YLlm-YLHyP8u-^t9$@^uDps~c+oz%s~T$(}8=Cnj`Oe){;UCu{ohNdEciahopCe8fjLP=&rc?bQjRaz2g9OL0eXrYWlNW>^`Y=K7TXsyet6@dMG0?lUbnG4XhvL0Pf)-Q?)2eU;h3908y?&BIr3FI91~Q#7H9ta2@bDwBRNuShAK9|&3WMjc?#OXLQjzdva??x04GZ!Ry<X`FtjsF6Be?e~+b;jSu{k~7-wF0XQ%yp|(rS3_-F!v(5_F>lS^rP8{aBCFjE)~Ca4qDNJ*37~T0ZHO4^)^*#`rB<~$Tya`erxkk=T)KaK;>&c<*M*pId6Su&&?3-ENDZ-8deqy6n{j>Ah9a)hjIfBiP0WdH%D(r}7KI;X9laOn*J)tbqPQAWIt`3UQ2!=7cg^7Wx@;OCk7|Kmo${z9Hr~QCL+CbW`B|-c?<-J~{FFEWZ$2L~7-gb1_13Uu(BKjJvsORN0XFEe$)JM}=pJgU&^J+R`tZt7b#+~MwTU%;pY~?^EZ>ODTIPJa$<$!OEn7VU_*RbRFu7tM*t#Xt9Nt^nI$u`%_6yEC%&S47)T~GwCaCZ*<(-Ph=O0)1D`B^>G>!b5($>QtYPGo48P??ltE@muZ0<<|)JBeY!!~$dSUud27p#4NzwBHRn!>|pm44-Z4HW<oixVTA`WWfDmNqoq5F9u_Qzq`|rb*|BZDSkvI$PmllTu%fVfzSI;$o7o`(Wq>9A(bb;Y?+|wd1SJi1oK-t<UnRh7LZWDg#!Zc#Xo!S%&NOQB;>i+-7tX3WL{|HC#Gr5G;FXz*S^~h;%9#Tc!2O!moOl8SP!D*&oe)#umylHf{M~TJBJ9Y`fjXqR>RC_{Ey3tDDr>#A3Hm%F6Y&ovs0#(0=NyRzaT>p$&6|JGO|Z%T7$=$Xm<p^}FuWH`~`ICWfQ1DH#SRn6jEANe5GRoiV%x>s6W_$|wVRp8D<Akv6JW#G$-+X{>Z9nw=6E`K|ZFrK)&a(rElFva*Vzs@8_+CWLDbtE^S%(;-`C64~T1oiU`3maxo5l`lRWbhCG!3QL;|T<Sx!oK`NA+pSBocE+7ulW){kztz6ovYpm0*m7v=B2kA}#n+0O?QIJdl$hRv1}Ck*H6E7NTM@CNaVI1;Lm^Hq7{o~fMyb_pOMwogy5arv>i+;Hy{wP"
CATALOG = json.loads(zlib.decompress(base64.b85decode(_CATALOG_B85)).decode("utf-8"))
_BY_PATH = {entry["path"]: entry for entry in CATALOG}


def search_catalog(query: str) -> list[dict]:
    """Return entries containing every whitespace-separated term."""
    terms = query.casefold().split()
    if not terms:
        return list(CATALOG)
    matches = []
    for entry in CATALOG:
        haystack = "\n".join((entry["path"], entry["usage"], " ".join(entry["flags"]), entry["help"])).casefold()
        if all(term in haystack for term in terms):
            matches.append(entry)
    return matches


def make_preview(path: str, argument_text: str = "") -> str:
    """Format a catalog command and arguments without executing it."""
    if path not in _BY_PATH:
        raise ValueError("unknown catalog command path")
    if len(argument_text) > 4096:
        raise ValueError("argument preview is limited to 4096 characters")
    try:
        arguments = shlex.split(argument_text, posix=True)
    except ValueError as exc:
        raise ValueError(f"invalid argument quoting: {exc}") from exc
    return shlex.join(path.split() + arguments)


class LiveCommand(NamedTuple):
    label: str
    argv: tuple[str, ...]
    description: str
    resource_prompt: str = ""


class RunResult(NamedTuple):
    command_id: str
    argv: tuple[str, ...]
    status: str
    output: str
    returncode: int | None
    elapsed: float


# Every executable path is represented here as argv, never as shell text.  The
# catalog help for build 20260930 is the source of these exact read-only forms.
LIVE_COMMANDS = {
    "vm.list": LiveCommand("Virtual machines", ("hvmcli", "vm", "list", "--details"), "VM state, CPU, memory, and disks"),
    "node.list": LiveCommand("Node summary", ("hvmcli", "node", "list"), "Hardware, OS, and node configuration"),
    "node.config": LiveCommand("Node configuration", ("hvmcli", "node", "show-config"), "Current NTP, DNS, proxy, locale, timezone, and logging"),
    "interfaces.list": LiveCommand("Network interfaces", ("hvmcli", "interfaces", "list"), "Ethernet, FC, and managed interfaces"),
    "hardware.cpu": LiveCommand("CPU inventory", ("hvmcli", "hardware", "cpu", "list"), "CPU model and topology"),
    "hardware.memory": LiveCommand("Memory inventory", ("hvmcli", "hardware", "memory", "list"), "Memory and swap capacity"),
    "hardware.pci": LiveCommand("PCI inventory", ("hvmcli", "hardware", "pci", "list"), "PCI devices"),
    "hardware.bootvolume": LiveCommand("Boot volume", ("hvmcli", "hardware", "bootvolume", "list"), "Root and boot backing storage"),
    "software.list": LiveCommand("Installed software", ("hvmcli", "software", "list"), "Installed qemu, libvirt, kernel, and hvmcli versions"),
    "virtswitch.list": LiveCommand("virtSwitch list", ("hvmcli", "virtswitch", "list"), "Managed virtSwitch configuration"),
    "virtswitch.status": LiveCommand("virtSwitch status", ("hvmcli", "virtswitch", "status"), "Operational status for all virtSwitches"),
    "virtswitch.show": LiveCommand("virtSwitch details", ("hvmcli", "virtswitch", "show"), "Detailed view for one named virtSwitch", "virtSwitch name: "),
    "network.list": LiveCommand("Virtual networks", ("hvmcli", "network", "list"), "Configured virtual networks"),
    "storage.list": LiveCommand("Storage pools", ("hvmcli", "storage", "list"), "Configured storage pools"),
    "storage.iscsi.sessions": LiveCommand("iSCSI sessions", ("hvmcli", "storage", "iscsi", "--list"), "Established iSCSI sessions"),
    "storage.iscsi.multipath": LiveCommand("iSCSI multipath", ("hvmcli", "storage", "iscsi", "--multipath"), "iSCSI-backed multipath maps"),
    "storage.fc.ports": LiveCommand("FC HBA ports", ("hvmcli", "storage", "fc", "--list"), "Fibre Channel HBA ports"),
    "storage.fc.multipath": LiveCommand("FC multipath", ("hvmcli", "storage", "fc", "--multipath"), "FC-backed multipath maps"),
    "storage.multipath.status": LiveCommand("Multipath status", ("hvmcli", "storage", "multipath", "status"), "All multipath devices and state"),
    "storage.multipath.validate": LiveCommand("Multipath validation", ("hvmcli", "storage", "multipath", "validate"), "Parser, daemon, and map visibility checks"),
    "cluster.status": LiveCommand("Cluster status", ("hvmcli", "cluster", "status"), "Cluster and quorum status"),
    "cluster.nodes": LiveCommand("Cluster nodes", ("hvmcli", "cluster", "nodes", "--list"), "Cluster node status and role"),
    "health.check": LiveCommand("Health check", ("hvmcli", "health", "check"), "One bounded host readiness check (never watch)"),
    "logs.node": LiveCommand("Recent node log", ("hvmcli", "logs", "node"), "Non-streaming node syslog (captured and size-bounded)"),
    "logs.cluster": LiveCommand("Recent cluster log", ("hvmcli", "logs", "cluster"), "Non-streaming cluster/pcs log (captured and size-bounded)"),
    "logs.morpheus": LiveCommand("Recent Morpheus agent log", ("hvmcli", "logs", "morpheus-agent"), "Non-streaming agent log (captured and size-bounded)"),
    "node.events": LiveCommand("Recent warning events", ("hvmcli", "node", "events", "--priority", "warning", "--lines", "100"), "Most recent 100 warning-or-higher journal events"),
}

_RESOURCE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)\S+"),
    re.compile(r"(?i)((?:api[_-]?key|token|password|secret)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(://[^\s/:@]+:)[^\s/@]+(@)"),
)


def redact_output(text: str) -> str:
    """Remove terminal controls and mask common credential shapes."""
    text = _CONTROL_RE.sub("", _ANSI_RE.sub("", text))
    for index, pattern in enumerate(_SECRET_PATTERNS):
        if index == 2:
            text = pattern.sub(r"\1[REDACTED]\2", text)
        else:
            text = pattern.sub(r"\1[REDACTED]", text)
    return text


class CommandRunner:
    """Run allowlisted argv with no shell, a deadline, and a byte ceiling."""

    def __init__(self, timeout: float = 15.0, max_output: int = 256 * 1024):
        if timeout <= 0 or max_output < 256:
            raise ValueError("timeout must be positive and max_output at least 256 bytes")
        self.timeout = timeout
        self.max_output = max_output

    def run_sync(self, command_id: str, *, executable: str | None = None, resource: str = "") -> RunResult:
        if command_id not in LIVE_COMMANDS:
            raise ValueError("command is not in the read-only allowlist")
        command = LIVE_COMMANDS[command_id]
        argv = list(command.argv)
        if command.resource_prompt:
            if not _RESOURCE_RE.fullmatch(resource):
                raise ValueError("resource name must contain only letters, numbers, dot, colon, underscore, or dash")
            argv.extend(("--virtswitch-name", resource))
        elif resource:
            raise ValueError("this command does not accept a resource")
        argv[0] = executable or argv[0]
        display_argv = tuple(("hvmcli", *argv[1:]))
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                argv, shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"},
            )
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return RunResult(command_id, display_argv, "error", f"hvmcli not found or unavailable: {exc}", None, time.monotonic() - started)

        data = bytearray()
        status = "ok"
        selector = selectors.DefaultSelector()
        assert process.stdout is not None
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while True:
                elapsed = time.monotonic() - started
                if elapsed >= self.timeout:
                    status = "timeout"
                    process.kill()
                    break
                events = selector.select(min(0.05, self.timeout - elapsed))
                for key, _ in events:
                    chunk = os.read(key.fileobj.fileno(), min(8192, self.max_output - len(data) + 1))
                    if chunk:
                        data.extend(chunk)
                        if len(data) > self.max_output:
                            del data[self.max_output:]
                            status = "truncated"
                            process.kill()
                            break
                if status != "ok":
                    break
                if process.poll() is not None:
                    # Drain the final pipe bytes after process exit.
                    chunk = os.read(process.stdout.fileno(), min(8192, self.max_output - len(data) + 1))
                    if chunk:
                        data.extend(chunk)
                        if len(data) > self.max_output:
                            del data[self.max_output:]
                            status = "truncated"
                    break
        finally:
            selector.close()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
            process.stdout.close()
        elapsed = time.monotonic() - started
        if status == "ok" and process.returncode:
            status = "error"
        output = data.decode("utf-8", "replace")
        if status == "timeout":
            output += f"\n\n[Timed out after {self.timeout:g} seconds; process killed.]"
        elif status == "truncated":
            output += f"\n\n[Output truncated at {self.max_output} bytes; process killed.]"
        elif status == "error" and not output:
            output = f"hvmcli exited with status {process.returncode}."
        return RunResult(command_id, display_argv, status, redact_output(output), process.returncode, elapsed)


class MenuItem(NamedTuple):
    label: str
    description: str = ""
    command_id: str = ""
    children: tuple["MenuItem", ...] = ()
    action: str = ""


def _commands(*ids: str) -> tuple[MenuItem, ...]:
    return tuple(MenuItem(LIVE_COMMANDS[item].label, LIVE_COMMANDS[item].description, item) for item in ids)


MENU_ROOT = (
    MenuItem("System", "Node configuration, software, and hardware", children=(
        MenuItem("Node", children=_commands("node.list", "node.config", "software.list")),
        MenuItem("Hardware", children=_commands("hardware.cpu", "hardware.memory", "hardware.pci", "hardware.bootvolume")),
    )),
    MenuItem("Virtual machines", "Inventory only; no power actions", children=_commands("vm.list")),
    MenuItem("Networking", "Interfaces, networks, and virtSwitch diagnostics", children=(
        MenuItem("Interfaces and networks", children=_commands("interfaces.list", "network.list")),
        MenuItem("virtSwitch", children=_commands("virtswitch.list", "virtswitch.status", "virtswitch.show")),
    )),
    MenuItem("Storage", "Pools, FC, iSCSI, and multipath status", children=_commands(
        "storage.list", "storage.iscsi.sessions", "storage.iscsi.multipath", "storage.fc.ports",
        "storage.fc.multipath", "storage.multipath.status", "storage.multipath.validate")),
    MenuItem("Cluster and health", "One-shot cluster and readiness checks", children=_commands(
        "cluster.status", "cluster.nodes", "health.check")),
    MenuItem("Problem logs", "Bounded, non-streaming diagnostic output", children=_commands(
        "node.events", "logs.node", "logs.cluster", "logs.morpheus")),
    MenuItem("Command help browser", "Browse all installed help; previews remain inert", action="catalog"),
)


class MenuState:
    def __init__(self, root: tuple[MenuItem, ...]):
        self.stack: list[tuple[str, tuple[MenuItem, ...], int]] = [("Main", root, 0)]

    @property
    def items(self) -> tuple[MenuItem, ...]: return self.stack[-1][1]
    @property
    def selected(self) -> int: return self.stack[-1][2]
    @selected.setter
    def selected(self, value: int) -> None:
        title, items, _ = self.stack[-1]
        self.stack[-1] = (title, items, max(0, min(value, max(0, len(items) - 1))))
    @property
    def breadcrumb(self) -> str: return " / ".join(frame[0] for frame in self.stack)
    @property
    def depth(self) -> int: return len(self.stack)

    def handle_key(self, key: int) -> bool:
        if key in (curses.KEY_DOWN, ord("j")): self.selected += 1
        elif key in (curses.KEY_UP, ord("k")): self.selected -= 1
        elif key in (10, 13, curses.KEY_RIGHT) and self.items:
            item = self.items[self.selected]
            if item.children: self.stack.append((item.label, item.children, 0))
        elif key in (27, curses.KEY_LEFT, curses.KEY_BACKSPACE):
            if len(self.stack) > 1: self.stack.pop()
            else: return True
        elif key == ord("q"): return True
        return False


class OutputView:
    def __init__(self, text: str = ""):
        self.set_text(text)

    def set_text(self, text: str) -> None:
        self.text = text
        self.lines = text.splitlines() or [""]
        self.offset = 0
        self.query = ""
        self.matches: list[int] = []
        self.match_index = -1

    def search(self, query: str) -> list[int]:
        self.query = query
        folded = query.casefold()
        self.matches = [i for i, line in enumerate(self.lines) if folded and folded in line.casefold()]
        self.match_index = 0 if self.matches else -1
        if self.matches: self.offset = self.matches[0]
        return self.matches

    def next_match(self) -> None:
        if self.matches:
            self.match_index = (self.match_index + 1) % len(self.matches)
            self.offset = self.matches[self.match_index]

    def scroll(self, delta: int, page_size: int) -> None:
        self.offset = max(0, min(self.offset + delta, max(0, len(self.lines) - max(1, page_size))))


def _html(nonce: str) -> bytes:
    page = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NodePilot — Browse Only</title>
<style nonce="__NONCE__">
:root{color-scheme:dark;--bg:#111820;--panel:#18232d;--line:#334553;--text:#e8eef2;--muted:#a9bac5;--accent:#5cc8b2;--warn:#ffd166}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,sans-serif}header{padding:1rem 1.25rem;border-bottom:1px solid var(--line)}h1{font-size:1.2rem;margin:0 0 .35rem}.warning{color:var(--warn);font-weight:700}.meta,.empty{color:var(--muted);font-size:.86rem}main{display:grid;grid-template-columns:minmax(17rem,32%) 1fr;height:calc(100vh - 6.2rem)}nav,article{overflow:auto;padding:1rem}nav{border-right:1px solid var(--line)}label{display:block;color:var(--muted);font-size:.82rem;margin:.6rem 0 .25rem}input{width:100%;padding:.65rem;background:#0c1319;color:var(--text);border:1px solid var(--line);border-radius:4px}.count{color:var(--muted);font-size:.8rem;margin:.55rem 0}.commands{display:grid;gap:.25rem}.commands button{background:transparent;color:var(--text);border:1px solid transparent;text-align:left;padding:.45rem .55rem;border-radius:3px;cursor:pointer}.commands button:hover,.commands button[aria-current=true]{border-color:var(--accent);background:#20333b}.path{font:600 1.05rem ui-monospace,monospace;color:var(--accent)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0c1319;border:1px solid var(--line);padding:.85rem;border-radius:4px}.preview{color:var(--warn)}@media(max-width:720px){main{display:block;height:auto}nav{border-right:0;border-bottom:1px solid var(--line);max-height:45vh}}
</style></head><body><header><h1>NodePilot</h1><div class="warning">HELP / COMMAND PREVIEW ONLY — NOTHING IS EXECUTED</div><div class="meta">Unofficial catalog for build 20260930 · 101 documented command/action paths</div></header>
<main><nav aria-label="Command catalog"><label for="search">Search paths, flags, and help</label><input id="search" type="search" autofocus autocomplete="off"><div id="count" class="count" aria-live="polite"></div><div id="commands" class="commands"></div></nav><article><div id="detail" class="empty">Select a documented command.</div></article></main>
<script nonce="__NONCE__">
'use strict';const token=new URLSearchParams(location.search).get('token')||'';history.replaceState({},'',location.pathname);const list=document.querySelector('#commands'),detail=document.querySelector('#detail'),search=document.querySelector('#search'),count=document.querySelector('#count');let catalog=[],selected=null;
function node(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n}
function show(entry){selected=entry;document.querySelectorAll('.commands button').forEach(b=>b.setAttribute('aria-current',String(b.dataset.path===entry.path)));detail.replaceChildren();detail.append(node('div',entry.path,'path'));detail.append(node('h2','Advertised usage'));detail.append(node('pre',entry.usage||'No dedicated usage line captured.'));detail.append(node('h2','Command preview (inert text only)'));const label=node('label','Optional arguments to append');label.htmlFor='args';const input=node('input');input.id='args';input.placeholder='e.g. --json';const out=node('pre',entry.path,'preview');input.addEventListener('input',()=>{out.textContent=entry.path+(input.value?' '+input.value:'')});detail.append(label,input,out);detail.append(node('h2','Captured help (sanitized)'));detail.append(node('pre',entry.help));}
function render(){const terms=search.value.toLowerCase().trim().split(/\s+/).filter(Boolean);const matches=catalog.filter(e=>terms.every(t=>(e.path+' '+e.flags.join(' ')+' '+e.help).toLowerCase().includes(t)));list.replaceChildren();count.textContent=matches.length+' of '+catalog.length+' commands';for(const e of matches){const b=node('button',e.path);b.type='button';b.dataset.path=e.path;b.addEventListener('click',()=>show(e));list.append(b)}if(matches.length&&(!selected||!matches.includes(selected)))show(matches[0]);if(!matches.length){selected=null;detail.replaceChildren(node('div','No matching commands.','empty'))}}
fetch('/api/catalog?token='+encodeURIComponent(token),{credentials:'same-origin'}).then(r=>{if(!r.ok)throw Error('Access denied');return r.json()}).then(data=>{catalog=data;render()}).catch(()=>{detail.textContent='Catalog access denied. Reopen the tokenized URL printed by the helper.'});search.addEventListener('input',render);
</script></body></html>'''
    return page.replace("__NONCE__", nonce).encode("utf-8")


def create_web_server(host: str = "127.0.0.1", port: int = 0, *, token: str | None = None):
    """Create a read-only HTTP server restricted to IPv4 loopback."""
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("web UI may bind only to 127.0.0.1 or localhost")
    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    session_token = token or secrets.token_urlsafe(32)
    if len(session_token) < 8:
        raise ValueError("session token must be at least 8 characters")
    nonce = secrets.token_urlsafe(18)

    class Handler(BaseHTTPRequestHandler):
        server_version = "NodePilot/0.2"
        sys_version = ""

        def _allowed_host(self) -> bool:
            value = self.headers.get("Host", "")
            port_now = self.server.server_address[1]
            return value in {"127.0.0.1", "localhost", f"127.0.0.1:{port_now}", f"localhost:{port_now}"}

        def _allowed_origin(self) -> bool:
            origin = self.headers.get("Origin")
            if origin is None:
                return True
            port_now = self.server.server_address[1]
            return origin in {f"http://127.0.0.1:{port_now}", f"http://localhost:{port_now}"}

        def _token_ok(self, parsed) -> bool:
            values = urllib.parse.parse_qs(parsed.query, keep_blank_values=True).get("token", [])
            return len(values) == 1 and hmac.compare_digest(values[0], session_token)

        def _headers(self, status: int, content_type: str, length: int) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", f"default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.end_headers()

        def _reply(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8", *, head: bool = False) -> None:
            self._headers(status, content_type, len(body))
            if not head:
                self.wfile.write(body)

        def _serve(self, head: bool = False) -> None:
            if not self._allowed_host():
                self._reply(421, b"Untrusted Host\n", head=head); return
            if not self._allowed_origin():
                self._reply(403, b"Untrusted Origin\n", head=head); return
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path not in {"/", "/api/catalog"}:
                self._reply(404, b"Not found\n", head=head); return
            if not self._token_ok(parsed):
                self._reply(403, b"A valid local session token is required.\n", head=head); return
            if parsed.path == "/":
                body = _html(nonce); ctype = "text/html; charset=utf-8"
            else:
                body = json.dumps(CATALOG, separators=(",", ":")).encode("utf-8"); ctype = "application/json; charset=utf-8"
            self._reply(200, body, ctype, head=head)

        def do_GET(self): self._serve()
        def do_HEAD(self): self._serve(head=True)
        def _method_not_allowed(self):
            self.send_response(405); self.send_header("Allow", "GET, HEAD"); self.send_header("Content-Length", "0"); self.end_headers()
        do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _method_not_allowed
        def log_message(self, _format, *_args): pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server, session_token


def _safe_add(win, y: int, x: int, text: str, width: int, attr: int = 0) -> None:
    if y < 0 or x < 0 or width <= 0:
        return
    try:
        win.addnstr(y, x, text, width, attr)
    except curses.error:
        pass


def _prompt(stdscr, label: str) -> str | None:
    height, width = stdscr.getmaxyx(); curses.echo(); curses.curs_set(1)
    try:
        stdscr.move(height - 1, 0); stdscr.clrtoeol(); _safe_add(stdscr, height - 1, 0, label, max(1, width - 1), curses.A_BOLD)
        raw = stdscr.getstr(height - 1, min(len(label), width - 1), max(1, width - len(label) - 1))
        return raw.decode("utf-8", "replace")
    except (curses.error, KeyboardInterrupt):
        return None
    finally:
        curses.noecho()
        try: curses.curs_set(0)
        except curses.error: pass


def _catalog_browser(stdscr) -> None:
    """Browse embedded help only; no execution is reachable from this view."""
    query = ""; selected = 0; scroll = 0; preview = ""
    while True:
        matches = search_catalog(query)
        selected = min(selected, max(0, len(matches) - 1))
        stdscr.erase(); height, width = stdscr.getmaxyx()
        _safe_add(stdscr, 0, 1, " COMMAND HELP — BROWSE / PREVIEW ONLY ", width - 2, curses.A_BOLD)
        _safe_add(stdscr, 1, 1, f"Main / Help catalog   Search: {query or '(all)'}   {len(matches)}/{len(CATALOG)}", width - 2)
        if height < 10 or width < 50:
            _safe_add(stdscr, 3, 1, "Terminal too small (minimum 50x10).", width - 2, curses.A_BOLD)
        elif not matches:
            _safe_add(stdscr, 3, 2, "No matching commands.", width - 4)
        else:
            left = min(42, max(25, width // 3)) if width >= 78 else width - 2
            visible = max(1, height - 5)
            top = max(0, min(selected - visible // 2, max(0, len(matches) - visible)))
            for row, entry in enumerate(matches[top:top + visible], 3):
                idx = top + row - 3
                _safe_add(stdscr, row, 2, entry["path"], left - 3, curses.A_REVERSE if idx == selected else 0)
            if width >= 78:
                entry = matches[selected]
                detail = [entry["path"], "", "Usage:", entry["usage"] or "(no dedicated usage)", "",
                          "Flags: " + (" ".join(entry["flags"]) or "(none)"), "", "Captured help:"] + entry["help"].splitlines()
                if preview: detail += ["", "INERT PREVIEW — NOT EXECUTED:", preview]
                wrapped: list[str] = []
                for line in detail:
                    wrapped.extend(textwrap.wrap(line, max(10, width - left - 4), replace_whitespace=False, drop_whitespace=False) or [""])
                scroll = min(scroll, max(0, len(wrapped) - visible))
                for row, line in enumerate(wrapped[scroll:scroll + visible], 3):
                    _safe_add(stdscr, row, left + 1, line, width - left - 3)
        _safe_add(stdscr, height - 1, 1, "↑↓ select  PgUp/PgDn scroll  / search  p inert preview  Esc back", width - 2, curses.A_REVERSE)
        stdscr.refresh(); key = stdscr.getch()
        if key in (27, ord("q")): return
        if key in (curses.KEY_DOWN, ord("j")) and matches: selected = min(selected + 1, len(matches) - 1); scroll = 0; preview = ""
        elif key in (curses.KEY_UP, ord("k")) and matches: selected = max(0, selected - 1); scroll = 0; preview = ""
        elif key == curses.KEY_NPAGE: scroll += max(1, height - 6)
        elif key == curses.KEY_PPAGE: scroll = max(0, scroll - max(1, height - 6))
        elif key == ord("/"):
            value = _prompt(stdscr, "Help search: ")
            if value is not None: query = value; selected = scroll = 0; preview = ""
        elif key == ord("p") and matches:
            value = _prompt(stdscr, "Arguments (preview only): ")
            if value is not None:
                try: preview = make_preview(matches[selected]["path"], value)
                except ValueError as exc: preview = f"Error: {exc}"


def _draw_frame(stdscr, height: int, width: int) -> None:
    if height < 2 or width < 2: return
    _safe_add(stdscr, 0, 0, "+" + "-" * max(0, width - 2) + "+", width)
    for row in range(1, height - 1):
        _safe_add(stdscr, row, 0, "|", 1); _safe_add(stdscr, row, width - 1, "|", 1)
    _safe_add(stdscr, height - 1, 0, "+" + "-" * max(0, width - 2) + "+", width)


def _curses_main(stdscr) -> None:
    try: curses.curs_set(0)
    except curses.error: pass
    stdscr.keypad(True); stdscr.timeout(100)
    if curses.has_colors():
        curses.start_color(); curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLUE)
        curses.init_pair(3, curses.COLOR_BLUE, curses.COLOR_WHITE)
        stdscr.bkgd(" ", curses.color_pair(1))
    state = MenuState(MENU_ROOT)
    view = OutputView("Select a category. All live actions are read-only and run only on Enter.")
    runner = CommandRunner()
    results: queue.Queue[RunResult | Exception] = queue.Queue(maxsize=1)
    worker: threading.Thread | None = None
    last_command = ""; last_resource = ""; status = "Ready"

    def start_command(command_id: str, resource: str = "") -> None:
        nonlocal worker, last_command, last_resource, status
        if worker and worker.is_alive(): status = "A read-only command is already running"; return
        last_command, last_resource = command_id, resource
        command = LIVE_COMMANDS[command_id]
        shown = list(command.argv)
        if resource: shown += ["--virtswitch-name", resource]
        view.set_text("Running in background...\n\n$ " + shlex.join(shown))
        status = "Running (15s timeout)..."
        def work() -> None:
            try: results.put(runner.run_sync(command_id, resource=resource))
            except Exception as exc: results.put(exc)
        worker = threading.Thread(target=work, name="hvmcli-readonly", daemon=True); worker.start()

    while True:
        try:
            result = results.get_nowait()
            if isinstance(result, Exception):
                status = "Error"; view.set_text(f"Unable to run command: {result}")
            else:
                status = f"{result.status.upper()} | rc={result.returncode} | {result.elapsed:.2f}s"
                heading = "$ " + shlex.join(result.argv) + f"\nStatus: {status}\n" + "-" * 50
                view.set_text(heading + "\n" + (result.output or "(command returned no output)"))
        except queue.Empty: pass

        stdscr.erase(); height, width = stdscr.getmaxyx()
        if height < 12 or width < 60:
            _safe_add(stdscr, 0, 0, "NodePilot", max(1, width - 1), curses.A_BOLD)
            _safe_add(stdscr, 2, 0, "Terminal too small. Resize to at least 60x12.", max(1, width - 1), curses.A_BOLD)
            _safe_add(stdscr, max(0, height - 1), 0, "q quit", max(1, width - 1), curses.A_REVERSE)
            stdscr.refresh(); key = stdscr.getch()
            if key in (ord("q"), 27): return
            continue

        _draw_frame(stdscr, height, width)
        header_attr = curses.color_pair(2) | curses.A_BOLD if curses.has_colors() else curses.A_BOLD
        _safe_add(stdscr, 1, 2, " HPE VM ESSENTIALS — READ-ONLY HELPER ", width - 4, header_attr)
        _safe_add(stdscr, 2, 2, state.breadcrumb, width - 4, curses.A_BOLD)
        # Keep row 3 blank as breathing room between breadcrumb and pane headings.
        split = min(39, max(27, width // 3)); body_top = 5; body_bottom = height - 3
        for row in range(body_top, body_bottom + 1): _safe_add(stdscr, row, split, "|", 1)
        _safe_add(stdscr, 4, 2, " MENU ", split - 3, curses.A_BOLD)
        _safe_add(stdscr, 4, split + 2, " LIVE INFORMATION / DIAGNOSTICS ", width - split - 4, curses.A_BOLD)
        visible_menu = max(1, body_bottom - body_top)
        top = max(0, min(state.selected - visible_menu // 2, max(0, len(state.items) - visible_menu)))
        for row, item in enumerate(state.items[top:top + visible_menu], body_top + 1):
            index = top + row - body_top - 1
            suffix = "  >" if item.children else ""
            attr = curses.A_REVERSE | curses.A_BOLD if index == state.selected else 0
            _safe_add(stdscr, row, 2, item.label + suffix, split - 4, attr)
        if state.items:
            selected_item = state.items[state.selected]
            _safe_add(stdscr, body_bottom, 2, selected_item.description, split - 4, curses.A_DIM)

        output_width = width - split - 4; output_height = max(1, body_bottom - body_top)
        for row, line in enumerate(view.lines[view.offset:view.offset + output_height], body_top + 1):
            attr = curses.A_BOLD if view.query and view.query.casefold() in line.casefold() else 0
            _safe_add(stdscr, row, split + 2, line, output_width, attr)
        position = f"line {min(view.offset + 1, len(view.lines))}/{len(view.lines)}"
        if view.query: position += f" | find '{view.query}' {len(view.matches)} match(es)"
        _safe_add(stdscr, body_bottom, split + 2, position, output_width, curses.A_DIM)
        _safe_add(stdscr, height - 2, 2, f" {status} ", width - 4, curses.A_BOLD)
        footer = "↑↓ navigate  Enter open/run  Esc back  r refresh  PgUp/PgDn scroll  / find  n next  q quit"
        _safe_add(stdscr, height - 1, 1, footer, width - 2, curses.A_REVERSE)
        stdscr.refresh(); key = stdscr.getch()
        if key == -1: continue

        item = state.items[state.selected] if state.items else None
        if key in (10, 13, curses.KEY_RIGHT) and item:
            if item.children: state.handle_key(key); view.set_text(item.description or "Select a read-only view."); status = "Ready"
            elif item.action == "catalog": _catalog_browser(stdscr); status = "Returned from browse-only help"
            elif item.command_id:
                resource = ""
                prompt = LIVE_COMMANDS[item.command_id].resource_prompt
                if prompt:
                    entered = _prompt(stdscr, prompt)
                    if entered is None: continue
                    resource = entered.strip()
                    if not _RESOURCE_RE.fullmatch(resource):
                        status = "Invalid resource name"; view.set_text("Use only letters, numbers, dot, colon, underscore, or dash (maximum 128).")
                        continue
                start_command(item.command_id, resource)
        elif key == ord("r") and last_command: start_command(last_command, last_resource)
        elif key == curses.KEY_NPAGE: view.scroll(max(1, output_height - 1), output_height)
        elif key == curses.KEY_PPAGE: view.scroll(-max(1, output_height - 1), output_height)
        elif key == ord("/"):
            entered = _prompt(stdscr, "Find in output: ")
            if entered is not None:
                view.search(entered); status = f"Find: {len(view.matches)} match(es)"
        elif key == ord("n"): view.next_match()
        elif state.handle_key(key): return


def run_tui() -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("TUI requires an interactive terminal. Use 'list', 'search', or 'web'.", file=sys.stderr); return 2
    try: curses.wrapper(_curses_main)
    except curses.error as exc:
        print(f"Unable to start curses TUI: {exc}", file=sys.stderr); return 2
    return 0


def run_web(host: str, port: int, open_browser: bool) -> int:
    server, token = create_web_server(host, port)
    actual_port = server.server_address[1]
    url = f"http://127.0.0.1:{actual_port}/?token={urllib.parse.quote(token)}"
    print(SAFETY); print(f"Local URL: {url}"); print("Press Ctrl-C to stop.")
    if open_browser: webbrowser.open(url)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="NodePilot: unofficial host administration companion: fixed read-only live TUI; browse-only web/catalog interfaces.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION} ({CATALOG_BUILD})")
    sub = parser.add_subparsers(dest="mode")
    sub.add_parser("tui", help="open searchable curses interface (default)")
    web = sub.add_parser("web", help="serve optional loopback-only web interface")
    web.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "localhost"), help="loopback bind name only")
    web.add_argument("--port", type=int, default=0, help="local port; 0 chooses a free port")
    web.add_argument("--open-browser", action="store_true", help="open the tokenized local URL")
    sub.add_parser("list", help="print all documented paths")
    search = sub.add_parser("search", help="search paths, flags, usage, and help"); search.add_argument("query")
    show = sub.add_parser("show", help="print full sanitized help for one path"); show.add_argument("path")
    preview = sub.add_parser("preview", help="format inert command text; does not execute it"); preview.add_argument("path"); preview.add_argument("--args", default="", help="argument text (use --args='--flag value')")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.mode in (None, "tui"): return run_tui()
    if args.mode == "web": return run_web(args.host, args.port, args.open_browser)
    if args.mode == "list":
        for entry in CATALOG: print(entry["path"])
        return 0
    if args.mode == "search":
        matches = search_catalog(args.query)
        for entry in matches: print(entry["path"])
        return 0 if matches else 1
    if args.mode == "show":
        entry = _BY_PATH.get(args.path)
        if not entry: print("Unknown catalog path.", file=sys.stderr); return 2
        print(entry["help"]); return 0
    if args.mode == "preview":
        try: print(make_preview(args.path, args.args)); return 0
        except ValueError as exc: print(f"Preview error: {exc}", file=sys.stderr); return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
