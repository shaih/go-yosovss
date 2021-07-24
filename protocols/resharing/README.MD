# YOSO resharing protocols

## Packages

We implemented 3 versions:
* `basic`: one without future broadcast. Should not be used
* `futurebrodcast`: same as basic with future broadcast. Too slow algorithmically. Furthermore the receiver holding committee verifications might not be enough.
* `auditor`: optimized version

## Variable names

We detail the variables used in the resharing protocol below

The naming convention used is that for a given round of resharing, the holding committee is indexed by <code>i</code>, 
the verification committee by <code>k</code>, the next holding committee (the one receiving from the current one) 
indexed by <code>j</code>, and the future broadcast committee indexed by <code>l</code>.

The dealer performs an initial Pedersen VSS of some message $m$ which results in the shares that go to the initial 
holding committee and also the verifications that go to everyone participating in the protocol.

Specifically, dealer $D$ performs a Pedersen VSS to obtain $n$ shares $(s_i^{(1)}, r_i^{(1)})$ for $i=1,\dots, n$ and 
verifications $\{A_0^{(1)},\dots,A_{t-1}^{(1)}\}$. 

The shares are distributed to an initial holding committee, $HC^{(1)}_1,\dots,HC^{(1)}_n$, where in the implementation
$HC^{(1)}_i$ would be a party with their <code>id</code> being the $i$th entry in the initial 
<code>committees.Hold</code> array that is a parameter in <code>StartCommitteePartyFB</code>. 

For each $i$, holding committee member $HC^{(\tau)}_i$ performs a $t$-of-$n$ sharing of $s^{(\tau)}_i$ to obtain shares 
$s^{(\tau)}_{i1},\dots s^{(\tau)}_{in}$, and also a sharing of $r_i^{(\tau)}$ to obtain shares 
$r^{(\tau)}_{i1},\dots r^{(\tau)}_{in}$. Then a second level of $t$-of-$n$ sharing is performed via a Pedersen VSS 
scheme for each $j=1,\dots, n$ on $s^{(\tau)}_{ij}$ to obtain shares 
$\{(s_{s_{ij} 1}^{(\tau)}, r_{s_{ij} 1}^{(\tau)}),\dots, (s_{s_{ij} n}^{(\tau)}, r_{s_{ij} n}^{(\tau)})\}$ and 
verifications $\{A_{s_{ij}0}^{(\tau)},\dots,A_{s_{ij}t-1}^{(\tau)}\}$

This likewise happens for each $j=1,\dots, n$ on $r^{(\tau)}_{ij}$ to obtain shares\\ 
$\{(s_{r_{ij} 1}^{(\tau)}, r_{r_{ij} 1}^{(\tau)}),\dots, (s_{r_{ij} n}^{(\tau)}, r_{r_{ij} n}^{(\tau)})\}$ and 
verifications $\{A_{r_{ij}0}^{(\tau)},\dots,A_{r_{ij}t-1}^{(\tau)}\}$

This is what occurs in <code>TwoLevelShare</code>, which is called by each holding committee member. 
<code>TwoLevelShare</code> takes in $s^{(\tau)}_i$ and $s^{(\tau)}_i$ and outputs 5 things:
the first output, which is the <code>bi</code> matrix, is the $(s_{s_{ij} k}^{(\tau)}, r_{s_{ij} k}^{(\tau)})$ shares, which is represented as a 2-D array 
indexed first by $j$ and then followed by $k$. The second output is the list of verifications 
$\{A_{s_{ij}0}^{(\tau)},\dots,A_{s_{ij}t-1}^{(\tau)}\}$, stored as <code>vi</code>. 
The third output are the $(s_{r_{ij} k}^{(\tau)}, r_{r_{ij} k}^{(\tau)})$ shares, likewise indexed by $j$ followed by
$k$, stored as <code>di</code>, and the fourth output are a list of their verifications, $\{A_{r_{ij}0}^{(\tau)},\dots,A_{r_{ij}t-1}^{(\tau)}\}$,
stored as <code>wi</code>.
The fifth output are the verifications induced by the first level of sharing, namely 
$\{A_{i0}^{(\tau)},\dots,A_{it-1}^{(\tau)}\}$, stored as <code>ei</code>.

the names b, v, d, w, and e refer to these things throughout the entire protocol, with variable names
being modified versions of these names that reflects a subset of these shares or verifications, and perhaps
if they are in an encrypted form.

We additionally also have a representing the matrix of first level shares $s^{(\tau)}_{ij}$, as well as c representing the first
level shares of $r^{(\tau)}_{ij}$, also following the same rules of indexing.
