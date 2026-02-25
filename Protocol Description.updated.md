# Protocol Spec (WIP)


## 1. Goal


Compute the shuffled batch of Dodis–Yampolskiy OPRF outputs:
\[
Y_j = g^{(k + x_{\pi(j)})^{-1}} \quad \text{for } j=1,\dots,n
\]


where:
- Sender input: \(x_1,\dots,x_n\)
- Receiver input: permutation \(\pi\)
- \(k\) is secret-shared with BeDOZa-style authenticated shares


Both parties obtain the same ordered output list:
\[
(Y_1,\dots,Y_n)
=
\left(g^{(k + x_{\pi(1)})^{-1}}, \dots, g^{(k + x_{\pi(n)})^{-1}}\right)
\]


---


## 2. Algebraic Setting


- \(G\): cyclic group of prime order \(q\), generator \(g\)
- Scalars are in \(\mathbb{F}_q\)
- All field values are interpreted in \(\mathbb{F}_q\)


### DY-OPRF form
\[
\mathrm{DY}_k(x) := g^{(k+x)^{-1}}
\]


### Failure condition
Every inversion requires a nonzero denominator. (Abort/retry policy is implementation-defined and can be finalized later.)


---


## 3. Parties and Inputs


### Sender \(S\)
- Input values: \(X=(x_1,\dots,x_n)\)
- MAC key: \(\Delta_0\)


### Receiver \(R\)
- Input permutation: \(\pi\)
- MAC key: \(\Delta_1\)


### Shared secret
- BeDOZa-authenticated sharing of random key \(k\)


---


## 4. BeDOZa Authenticated Sharing (Variant Used Here)


### 4.1 Global MAC keys
- Sender holds \(\Delta_0\)
- Receiver holds \(\Delta_1\)


### 4.2 Sharing a value \(x\)
A value \(x \in \mathbb{F}_q\) is additively split as:
\[
x = x^0 + x^1
\]


- \(x^0\): Sender-side share
- \(x^1\): Receiver-side share


### 4.3 Local tuple notation for \(\llbracket x \rrbracket\)


- Sender holds:
  \[
  (x^0,\; u_x^0,\; v_x^1)
  \]


- Receiver holds:
  \[
  (x^1,\; u_x^1,\; v_x^0)
  \]


with:
\[
x = x^0 + x^1
\]
\[
v_x^0 = \Delta_1 x^0 - u_x^0
\]
\[
v_x^1 = \Delta_0 x^1 - u_x^1
\]


Interpretation:
- \(x^0\) (Sender share) is authenticated under \(\Delta_1\)
- \(x^1\) (Receiver share) is authenticated under \(\Delta_0\)


---


## 5. Notation and Placeholder APIs


### 5.1 Notation
- \(\llbracket x \rrbracket\): full BeDOZa-authenticated sharing (both additive shares + cross-MAC material)
- \(\langle x \rangle_{\Delta_0}^{R}\): Receiver-owned one-sided authenticated value under \(\Delta_0\) (Receiver holds \((x,u_x)\), Sender holds \(v_x=\Delta_0 x-u_x\))
- \(\langle x \rangle_{\Delta_1}^{S}\): Sender-owned one-sided authenticated value under \(\Delta_1\) (Sender holds \((x,u_x)\), Receiver holds \(v_x=\Delta_1 x-u_x\))
- `Permute_π(in)`: returns `out` with `out[i] = in[π(i)]` for \(i=1,\dots,n\)
- `Inv(a)`: field inverse \(a^{-1}\)
- `PowGen(a)`: \(g^a\)

Index convention:
- Public indices \(i \in \{1,\dots,n\}\) are encoded canonically as field elements in \(\mathbb{F}_q\)
- Require \(n < q\)


### 5.2 Placeholder subroutines (to be filled later)
- `auth_sender_owned_one_sided_under_Delta1(y)`
  - Output: Sender gets \((y,u_y)\), Receiver gets \(v_y\), with \(v_y=\Delta_1 y-u_y\)

- `auth_receiver_owned_one_sided_under_Delta0(y)`
  - Output: Receiver gets \((y,u_y)\), Sender gets \(v_y\), with \(v_y=\Delta_0 y-u_y\)


- `sVOLE_mul_shares(sender_vec_r, receiver_scalar_k1)`
  - Output additive shares of \((r_i \cdot k^1)_i\)


- `auth_sender_share_under_Delta1(x0)`
  - Authenticate Sender-owned share \(x^0\)


- `auth_receiver_share_under_Delta0(x1)`
  - Authenticate Receiver-owned share \(x^1\)


- `open_sender_share_to_receiver_under_Delta1(...)`
- `open_receiver_share_to_sender_under_Delta0(...)`


- `wolverine_linear_batch_check_Delta0(...)`
- `wolverine_linear_batch_check_Delta1(...)`
- `wolverine_batch_mul_proof_Delta0(...)`
- `wolverine_batch_mul_proof_Delta1(...)`
- `wolverine_circuit_prove_Delta0(...)`
- `wolverine_circuit_prove_Delta1(...)`


---


## 5A. Wolverine (Reusable Proof Machinery)


This section defines the Wolverine-style proof pattern used to prove correctness of multiplication gates and arithmetic circuits over authenticated values.


### 5A.1 Scope and convention


This protocol uses two symmetric variants:


- **Delta0-side Wolverine**: for values owned/authenticated on the Receiver side (authenticated under Sender MAC key \(\Delta_0\))
- **Delta1-side Wolverine**: symmetric variant for values owned/authenticated on the Sender side (authenticated under Receiver MAC key \(\Delta_1\))


Formulas below are written for the **Delta0-side** variant. The Delta1-side variant is obtained by swapping party roles and \(\Delta_0 \leftrightarrow \Delta_1\).


---


### 5A.2 One-sided authenticated value (Receiver-owned, under \(\Delta_0\))


A Receiver-owned scalar \(x\) authenticated under \(\Delta_0\) is represented as:


- Receiver holds:
  \[
  (x,\; u_x)
  \]
- Sender holds:
  \[
  v_x
  \]


such that:
\[
v_x = \Delta_0 x - u_x
\]


---


### 5A.3 Single multiplication-gate proof (Delta0-side)


Goal: prove a multiplication gate
\[
c = a \cdot b
\]
where \(a,b,c\) are Receiver-owned and each is authenticated under \(\Delta_0\).


Receiver has:
\[
(a,u_a),\ (b,u_b),\ (c,u_c)
\]
Sender has:
\[
v_a,\ v_b,\ v_c
\]
with:
\[
v_a=\Delta_0 a-u_a,\quad v_b=\Delta_0 b-u_b,\quad v_c=\Delta_0 c-u_c
\]


#### Gate identity used by Wolverine


Sender computes:
\[
L := v_a v_b - v_c \Delta_0
\]


Receiver computes:
\[
\lambda := u_c - u_a b - u_b a
\]
\[
\mu := u_a u_b
\]


If \(c=ab\), then:
\[
L = \Delta_0 \lambda + \mu
\]


This is a linear relation in \(\Delta_0\).


#### What must be checked


Run a Wolverine linear-check subroutine to verify:
\[
L \stackrel{?}= \Delta_0 \lambda + \mu
\]


If the check fails, abort.


---


### 5A.4 Batched multiplication-gate proof (Delta0-side)


To prove many multiplication gates at once, collect triples:
\[
(a_j,b_j,c_j),\quad j=1,\dots,m
\]
and compute for each \(j\):
\[
L_j,\ \lambda_j,\ \mu_j
\]
as in §5A.3.


#### Batched reduction (random linear combination)


Derive random batching coefficients \(\eta_1,\dots,\eta_m \in \mathbb{F}_q\).


Compute:
\[
L^\star := \sum_{j=1}^m \eta_j L_j
\]
\[
\lambda^\star := \sum_{j=1}^m \eta_j \lambda_j
\]
\[
\mu^\star := \sum_{j=1}^m \eta_j \mu_j
\]


Then run one Wolverine linear check for:
\[
L^\star \stackrel{?}= \Delta_0 \lambda^\star + \mu^\star
\]


If the check fails, abort.


---


### 5A.5 Wolverine for an arithmetic circuit (generic pattern)


Wolverine can be used to prove correctness of an entire arithmetic circuit over authenticated values:


1. **Inputs**
   - public constants
   - authenticated secret/shared inputs already available


2. **Gate evaluation**
   - Receiver evaluates each gate locally (for Receiver-owned wire values)
   - For each multiplication gate output \(c=a\cdot b\):
     - Receiver computes and authenticates \(c\)
     - record the gate for Wolverine batching


3. **Gate correctness proof**
   - run batched Wolverine multiplication proof over all multiplication gates (using §5A.4)


4. **Final output check**
   - obtain authenticated output wire(s)
   - open final output(s) to the designated party
   - check against expected public target (e.g. \(0\) or \(1\))


If any sub-check fails, abort.


---


### 5A.6 Small example: prove \(s \cdot \sigma = 1\)


Let \(\sigma = 1/s\). Receiver authenticates \(s\), \(\sigma\), and:
\[
t = s \sigma
\]
under \(\Delta_0\).


Then Receiver proves (with one multiplication gate proof) that:
\[
t = s \sigma
\]
and opens \(t\) to Sender, who checks:
\[
t \stackrel{?}= 1
\]


---


### 5A.7 Placeholder APIs (recommended)


- `wolverine_linear_check_Delta0(L, lambda, mu) -> ok/fail`
- `wolverine_linear_check_Delta1(L, lambda, mu) -> ok/fail`


- `wolverine_batch_mul_proof_Delta0(gates) -> ok/fail`
  - `gates[j]` contains authenticated Receiver-owned \((a_j,b_j,c_j)\)


- `wolverine_batch_mul_proof_Delta1(gates) -> ok/fail`
  - symmetric


- `wolverine_circuit_prove_Delta0(circuit, authenticated_inputs, expected_output) -> ok/fail`
- `wolverine_circuit_prove_Delta1(circuit, authenticated_inputs, expected_output) -> ok/fail`


---


## 5B. Batching linear relations in Wolverine (random linear combination)


This section specifies how to batch-check many linear relations of the form:
\[
L_j = \Delta \lambda_j + \mu_j
\]
where:
- \(\Delta\) is a MAC key (\(\Delta_0\) or \(\Delta_1\)),
- one party can compute \(L_j\),
- the other party can compute \((\lambda_j,\mu_j)\).


### 5B.1 Input format


For \(j=1,\dots,m\), each relation is represented as:
- prover-side values (known to party holding \(\Delta\)): \(L_j\)
- verifier-side values (known to the other party): \(\lambda_j,\mu_j\)


Target relation:
\[
L_j \stackrel{?}= \Delta \lambda_j + \mu_j
\]


### 5B.2 Random linear combination batching


Both parties derive fresh random coefficients:
\[
\eta_1,\dots,\eta_m \in \mathbb{F}_q
\]


Form:
\[
L^\star := \sum_{j=1}^m \eta_j L_j
\]
\[
\lambda^\star := \sum_{j=1}^m \eta_j \lambda_j
\]
\[
\mu^\star := \sum_{j=1}^m \eta_j \mu_j
\]


Check the single relation:
\[
L^\star \stackrel{?}= \Delta \lambda^\star + \mu^\star
\]


If this check fails, abort.


### 5B.3 API recommendation


- `wolverine_linear_batch_check_Delta0(L_list, lambda_list, mu_list) -> ok/fail`
- `wolverine_linear_batch_check_Delta1(L_list, lambda_list, mu_list) -> ok/fail`


Internal flow:
1. derive \(\eta_1,\dots,\eta_m\)
2. aggregate \((L^\star,\lambda^\star,\mu^\star)\)
3. run one-shot linear check


---


## 6. Phase A — Compute \(b_i = 1/(r_i(x_i+k))\) and Prove Correctness


### Phase A — Step 1. Pre-shared authenticated key


Assume a random key \(k \in \mathbb{F}_q\) is already available as a BeDOZa-authenticated sharing.


Local authenticated share of \(k\):


- Sender holds:
  \[
  (k^0, u_k^0, v_k^1)
  \]


- Receiver holds:
  \[
  (k^1, u_k^1, v_k^0)
  \]


with:
\[
k = k^0 + k^1
\]


\[
v_k^0 = \Delta_1 k^0 - u_k^0
\]
\[
v_k^1 = \Delta_0 k^1 - u_k^1
\]


---


### Phase A — Step 2. Sender local random masking values


Sender samples random nonzero field elements:
\[
r_1, r_2, \dots, r_n \xleftarrow{\$} \mathbb{F}_q^\times
\]


Sender locally computes, for each \(i\):
\[
y_i = r_i \cdot (x_i + k^0)
\]


All operations are in \(\mathbb{F}_q\).


No message is sent in this step.


---


### Phase A — Step 3. Sender authenticates \(y_1,\dots,y_n\) to Receiver (under \(\Delta_1\))


For each \(i\), Sender authenticates \(y_i\) under Receiver’s MAC key \(\Delta_1\), without splitting \(y_i\).


At the end of this step, for each \(i\):


- Sender holds:
  \[
  (u_{y_i}, y_i)
  \]


- Receiver holds:
  \[
  v_{y_i}
  \]


such that:
\[
v_{y_i} = \Delta_1 y_i - u_{y_i}
\]


No value \(y_i\) is opened in this step.


<!-- This can be implemented via VOLE.
Keep this as a placeholder share() operation for now, e.g.
auth_sender_owned_one_sided_under_Delta1(y_i) -> (Sender: (y_i, u_{y_i}), Receiver: v_{y_i})
Fill in the concrete VOLE-based implementation later. -->


---


### Phase A — Step 4. Create authenticated BeDOZa shares of \(z_i = r_i \cdot k^1\)


For each \(i\), define:
\[
z_i := r_i \cdot k^1
\]


Goal: produce \(\llbracket z_i \rrbracket\), i.e.
- Sender: \((z_i^0, u_{z_i}^0, v_{z_i}^1)\)
- Receiver: \((z_i^1, u_{z_i}^1, v_{z_i}^0)\)


such that:
\[
z_i^0 + z_i^1 = r_i \cdot k^1
\]


#### Step 4.1 sVOLE multiplication sharing


Run sVOLE with:
- Sender inputs: \((r_1,\dots,r_n)\)
- Receiver input: \(k^1\)


sVOLE outputs additive shares \((z_i^0)_i\) to Sender and \((z_i^1)_i\) to Receiver such that:
\[
z_i^0 + z_i^1 = r_i \cdot k^1
\]


#### Step 4.2 Authenticate the two shares


For each \(i\):


- Sender authenticates \(z_i^0\) under \(\Delta_1\), yielding
  \[
  v_{z_i}^0 = \Delta_1 z_i^0 - u_{z_i}^0
  \]


- Receiver authenticates \(z_i^1\) under \(\Delta_0\), yielding
  \[
  v_{z_i}^1 = \Delta_0 z_i^1 - u_{z_i}^1
  \]


At the end of this step, \(\llbracket z_i \rrbracket\) is available for all \(i\).


---


### Phase A — Step 5. Locally combine \(y_i\) and \(z_i\) into authenticated shares of \(a_i = r_i(x_i+k)\)


For each \(i\), define:
\[
a_i := y_i + z_i = r_i(x_i + k^0) + r_i k^1 = r_i(x_i+k)
\]


No interaction is needed in this step.


#### Sender local computation


Sender currently has:
- \((y_i, u_{y_i})\)
- \((z_i^0, u_{z_i}^0, v_{z_i}^1)\)


Sender computes:
\[
a_i^0 = z_i^0 + y_i
\]
\[
u_{a_i}^0 = u_{y_i} + u_{z_i}^0
\]
\[
v_{a_i}^1 = v_{z_i}^1
\]


So Sender's local tuple is:
\[
(a_i^0, u_{a_i}^0, v_{a_i}^1)
\]


#### Receiver local computation


Receiver currently has:
- \(v_{y_i}\)
- \((z_i^1, u_{z_i}^1, v_{z_i}^0)\)


Receiver computes:
\[
a_i^1 = z_i^1
\]
\[
u_{a_i}^1 = u_{z_i}^1
\]
\[
v_{a_i}^0 = v_{y_i} + v_{z_i}^0
\]


So Receiver's local tuple is:
\[
(a_i^1, u_{a_i}^1, v_{a_i}^0)
\]


At the end of this step:
\[
\llbracket a_i \rrbracket \text{ is available, with } a_i = a_i^0 + a_i^1 = r_i(x_i+k)
\]


---


### Phase A — Step 6. Open Sender's share of \(a_i\) to Receiver (one-sided open)


Goal: allow Receiver to reconstruct \(a_i = r_i(x_i+k)\) for all \(i\).


For each \(i\), Sender opens its local share \(a_i^0\) (authenticated under \(\Delta_1\)) to Receiver.


#### Sender \(\to\) Receiver


Sender sends:
\[
(a_i^0,\; u_{a_i}^0)
\]


#### Receiver local verification and reconstruction


Receiver already has:
- \(a_i^1\)
- \(v_{a_i}^0\)
- \(\Delta_1\)


Receiver checks:
\[
v_{a_i}^0 \stackrel{?}= \Delta_1 a_i^0 - u_{a_i}^0
\]


If the check fails, abort.


If the check passes, Receiver reconstructs:
\[
a_i = a_i^0 + a_i^1
\]


At the end of this step, Receiver knows \(a_i = r_i(x_i+k)\) for all \(i\).


<!-- Placeholder: replace with exact batched BeDOZa open/MAC-check routine later. -->


---


### Phase A — Step 7. Receiver computes inverses and BeDOZa-shares \(b_i = a_i^{-1}\) to Sender


For each \(i\), Receiver computes:
\[
b_i = a_i^{-1}
\]


If any \(a_i = 0\), abort (or restart according to the retry policy).

Note:
- Because \(r_i \neq 0\) by construction, \(a_i = 0\) iff \(x_i + k = 0\).
- Thus Phase A aborts exactly on undefined DY-OPRF denominators (modulo implementation faults), not due to masking randomness.

Receiver then BeDOZa-shares each \(b_i\) to Sender, obtaining \(\llbracket b_i \rrbracket\):


- Sender gets:
  \[
  (b_i^0, u_{b_i}^0, v_{b_i}^1)
  \]
- Receiver gets:
  \[
  (b_i^1, u_{b_i}^1, v_{b_i}^0)
  \]


with:
\[
b_i = b_i^0 + b_i^1
\]
\[
v_{b_i}^0 = \Delta_1 b_i^0 - u_{b_i}^0
\]
\[
v_{b_i}^1 = \Delta_0 b_i^1 - u_{b_i}^1
\]


At this point:
- Receiver knows \(a_i\) and \(b_i\), and (from generation) also knows \(a_i^0,a_i^1,b_i^0,b_i^1\)
- Sender knows \(a_i^0\) and \(b_i^0\)


<!-- Placeholder: receiver_share_bedoza_to_sender(b_i) -->


---


### Phase A — Step 8. Wolverine proof that \(b_i = a_i^{-1}\)


This step proves correctness of the inversion shares by checking:
\[
(a_i^0+a_i^1)(b_i^0+b_i^1)=1
\]
using Wolverine-style checks plus a final MAC-checked open.


#### Step 8.1 Receiver computes and authenticates \(c_i^1 = a_i^1 b_i^1\)


For each \(i\), Receiver computes:
\[
c_i^1 = a_i^1 b_i^1
\]


Receiver authenticates \(c_i^1\) under Sender’s MAC key \(\Delta_0\) (one-sided auth):


- Receiver holds:
  \[
  (u_{c_i}^1, c_i^1)
  \]
- Sender holds:
  \[
  v_{c_i}^1
  \]


such that:
\[
v_{c_i}^1 = \Delta_0 c_i^1 - u_{c_i}^1
\]


<!-- Can be implemented via VOLE-based one-sided share/auth routine under Delta_0. -->


#### Step 8.2 Wolverine linear check for \(c_i^1 = a_i^1 b_i^1\)


For each \(i\), define the Sender-side expression:
\[
L_i := v_{a_i}^1 \cdot v_{b_i}^1 - v_{c_i}^1 \cdot \Delta_0
\]


If \(c_i^1 = a_i^1 b_i^1\), then:
\[
L_i = \Delta_0 \cdot \lambda_i + \mu_i
\]
where Receiver can compute:
\[
\lambda_i := u_{c_i}^1 - u_{a_i}^1 b_i^1 - u_{b_i}^1 a_i^1
\]
\[
\mu_i := u_{a_i}^1 u_{b_i}^1
\]


Run Wolverine linear checks (batched across all \(i\) using random linear combination).


If the check fails, abort.


#### Step 8.3 Locally form authenticated share of \(p_i = a_i b_i\)


For each \(i\), write:
\[
p_i = a_i b_i = (a_i^0+a_i^1)(b_i^0+b_i^1)
\]


Define:
\[
p_i^0 := a_i^0 b_i^0
\]
\[
p_i^1 := a_i^0 b_i^1 + a_i^1 b_i^0 + c_i^1
\]


Then:
\[
p_i^0 + p_i^1 = a_i b_i
\]


Receiver computes:
\[
u_{p_i}^1 := a_i^0 u_{b_i}^1 + b_i^0 u_{a_i}^1 + u_{c_i}^1
\]


Sender computes:
\[
v_{p_i}^1 := a_i^0 v_{b_i}^1 + b_i^0 v_{a_i}^1 + v_{c_i}^1
\]


So \(p_i^1\) is authenticated under \(\Delta_0\):
\[
v_{p_i}^1 = \Delta_0 p_i^1 - u_{p_i}^1
\]


#### Step 8.4 Open \(p_i = a_i b_i\) to Sender and check equals 1


Receiver opens \(p_i^1\) (with \(u_{p_i}^1\)) to Sender under \(\Delta_0\).


Sender verifies the MAC relation using \(v_{p_i}^1\), reconstructs:
\[
p_i = p_i^0 + p_i^1
\]
and checks:
\[
p_i \stackrel{?}= 1
\]


If any check fails, abort.


At the end of this step, Sender accepts that the shared \(b_i\) values are valid inverses of the reconstructed \(a_i\) values (subject to Wolverine soundness and the opening checks).


---


## 7. Phase B — Permute After Exponentiation


### 7.1 Problem statement (corrected target)


Given public bases \(g_1,\dots,g_n \in G\), authenticated exponent shares \(\llbracket x_i \rrbracket\), and Receiver permutation \(\pi\), the goal is to obtain:
\[
h_i = g_{\pi(i)}^{x_{\pi(i)}} \quad \text{for } i=1,\dots,n
\]
(i.e. compute \(t_i = g_i^{x_i}\), then permute the outputs.)


---


### Phase B — Step 1. Sender sends partial exponentiations and proves exponent-share consistency


For each \(i\), Sender has authenticated share tuple:
\[
(x_i^0, u_{x_i}^0, v_{x_i}^1)
\]
and Receiver has:
\[
(x_i^1, u_{x_i}^1, v_{x_i}^0).
\]


Sender locally computes:
\[
h_i^{(0)} := g_i^{x_i^0}
\]
\[
k_i^{(0)} := g_i^{u_{x_i}^0}
\]


#### Sender \(\to\) Receiver


Sender sends:
\[
\{h_i^{(0)}\}_{i=1}^n,\quad \{k_i^{(0)}\}_{i=1}^n
\]


Receiver will later combine \(h_i^{(0)}\) with its own exponent share \(x_i^1\) to get:
\[
t_i = g_i^{x_i} = g_i^{x_i^0+x_i^1} = h_i^{(0)} \cdot g_i^{x_i^1}.
\]


#### Batched proof of consistency with authenticated Sender shares


The proof checks that the exponents used in \(h_i^{(0)}\) and \(k_i^{(0)}\) are consistent with the authenticated Sender share relation:
\[
v_{x_i}^0 = \Delta_1 x_i^0 - u_{x_i}^0.
\]


##### Step 1.1 Derive batching coefficients


Both parties derive a shared seed (coin-toss / transcript-derived seed; exact method to be specified), and expand it into random coefficients:
\[
\rho_1,\dots,\rho_n \in \mathbb{F}_q.
\]


##### Step 1.2 Receiver batched check


Receiver checks:
\[
\left(\prod_{i=1}^n (h_i^{(0)})^{\rho_i}\right)^{\Delta_1}
\stackrel{?}=
\left(\prod_{i=1}^n (k_i^{(0)})^{\rho_i}\right)
\cdot
\left(\prod_{i=1}^n g_i^{\rho_i v_{x_i}^0}\right)
\]


If the check fails, abort.


If the check passes, Receiver accepts that the sent partial exponentiations are consistent with Sender's authenticated shares (up to batching soundness).


---


### Phase B — Step 2. Receiver commits/authenticates permutation and mask-related values


This step prepares authenticated values used later to prove correctness of shuffled masked exponentiations.


#### Step 2.1 Authenticate permutation values


Receiver authenticates the permutation values:
\[
\pi(1),\pi(2),\dots,\pi(n)
\]
(as field elements in \(\mathbb{F}_q\); canonical embedding of indices \(1,\dots,n\)).


At the end, each \(\pi(i)\) is available as a Receiver-owned one-sided authenticated value under \(\Delta_0\):
\[
\langle \pi(i) \rangle_{\Delta_0}^{R}
\quad\text{for } i=1,\dots,n.
\]


#### Step 2.2 Authenticate mask \(s\) and inverse \(\sigma=1/s\)


Receiver samples mask:
\[
s \xleftarrow{\$} \mathbb{F}_q^\times
\]
and defines:
\[
\sigma := s^{-1}
\]


Receiver authenticates \(s\) and \(\sigma\) as Receiver-owned one-sided authenticated values under \(\Delta_0\):
\[
\langle s \rangle_{\Delta_0}^{R},\quad \langle \sigma \rangle_{\Delta_0}^{R}.
\]

Receiver then proves:
\[
s \cdot \sigma = 1
\]
using Wolverine (e.g. one multiplication gate + open-to-Sender check equals \(1\)).


If the check fails, abort.


#### Step 2.2b Challenge \(c\) (must occur before \(\beta_i,\gamma_i\) are formed)

A fresh challenge \(c \in \mathbb{F}_q\) is fixed at this point (source to be finalized in the challenge-derivation section):
- either interactive (e.g. Sender samples and sends \(c\)),
- or coin-toss / transcript-derived (Fiat–Shamir style).

This challenge must be transcript-bound to all prior messages that determine:
- authenticated permutation values \(\pi(i)\),
- authenticated mask values \(s,\sigma\),
- and any relevant setup context for this Phase B execution.

The values \(\beta_i\) and \(\gamma_i\) defined below must be computed only after \(c\) is fixed.


#### Step 2.3 (updated). After challenge \(c\), authenticate \(\beta_i=c^{\pi(i)}/s\) and masked Receiver shares \(\gamma_i=x_{\pi(i)}^1 s\)


After \(c \in \mathbb{F}_q\) is fixed, Receiver computes for each \(i\):
\[
\beta_i := c^{\pi(i)} \cdot \sigma = \frac{c^{\pi(i)}}{s}
\]
\[
\gamma_i := x_{\pi(i)}^1 \cdot s
\]


Receiver authenticates all \(\beta_i\) and all \(\gamma_i\) as Receiver-owned one-sided authenticated values under \(\Delta_0\), obtaining:
\[
\langle \beta_i \rangle_{\Delta_0}^{R},\ \langle \gamma_i \rangle_{\Delta_0}^{R}
\quad\text{for } i=1,\dots,n.
\]


For the extended batch check below, it is also convenient to define (in original index order):
\[
\delta_i := x_i^1 \cdot s
\]


The \(\delta_i\) values can be handled in either of two ways:


- **Option A (recommended for implementation):** compute/authenticate \(\delta_i\) inside the same Wolverine circuit as intermediate multiplication outputs.
- **Option B:** authenticate \(\delta_i\) separately before the product check.


This spec assumes **Option A** unless stated otherwise.


#### Step 2.4 (updated). Extended batched product consistency check for \((\pi(i), \beta_i, \gamma_i)\)


This step extends the product-root check so that it also binds the shuffled masked Receiver shares
\[
\gamma_i = x_{\pi(i)}^1 s
\]
to the same permutation \(\pi\) and mask \(s\).


##### Values involved


- \(s\) (authenticated)
- \(\pi(i)\) (authenticated)
- \(\sigma = 1/s\) (authenticated)
- \(\beta_i = c^{\pi(i)} \sigma = c^{\pi(i)}/s\) (authenticated)
- \(\gamma_i = x_{\pi(i)}^1 s\) (authenticated)
- \(\delta_i = x_i^1 s\) (computed/authenticated inside this circuit; see Step 2.3)


##### Sender challenge


Sender samples random field elements and sends them to Receiver:
\[
p,q,r,t \xleftarrow{\$} \mathbb{F}_q
\]


##### Product-identity relation to prove (via Wolverine circuit proof)


Both parties prove the arithmetic relation:
\[
\prod_{i=1}^n \Bigl(p - q i - r\, c^i \sigma - t\, \delta_i\Bigr)
\;-\;
\prod_{i=1}^n \Bigl(p - q \pi(i) - r\, \beta_i - t\, \gamma_i\Bigr)
= 0
\]


Interpretation (multiset equality):
- Left side encodes tuples in original order:
  \[
  (i,\ c^i/s,\ x_i^1 s)
  \]
- Right side encodes tuples in Receiver-permuted order:
  \[
  (\pi(i),\ c^{\pi(i)}/s,\ x_{\pi(i)}^1 s)
  \]


##### Wolverine implementation pattern (recommended)


Implement this as one Wolverine circuit proof:


1. Circuit inputs:
   - authenticated \(s\), \(\pi(i)\), \(\sigma\), \(x_i^1\), \(\beta_i\), \(\gamma_i\)
   - public constants \(i, c^i, p,q,r,t\)


2. Circuit computes:
   - \(\delta_i = x_i^1 \cdot s\) (or uses pre-authenticated \(\delta_i\))
   - each linear factor on both sides
   - both products
   - final difference


3. For every multiplication gate:
   - Receiver computes gate output
   - Receiver authenticates gate output
   - record gate for Wolverine batching


4. Run batched Wolverine multiplication-gate proof (Delta0-side for Receiver-owned wires)


5. Open final difference and check it equals \(0\)


If any check fails, abort.


##### Effect of this step


This single batched check binds together (in one proof):
- permutation values \(\pi(i)\),
- inverse mask \(\sigma=1/s\),
- challenge-derived values \(\beta_i=c^{\pi(i)}/s\),
- shuffled masked Receiver shares \(\gamma_i=x_{\pi(i)}^1 s\).


This removes the need for a separate proof that the \(\gamma_i\) values are a consistent shuffle of masked Receiver shares.


---


### Phase B — Step 3. Receiver sends first masked shuffled batch and proves correctness


This step proves correctness of the first masked shuffled batch:
\[
\widetilde{h}_i^{(0)} := \left(h_{\pi(i)}^{(0)}\right)^s
\]


#### Step 3.1 Receiver computes and sends masked shuffled values


Receiver has the list \(\{h_i^{(0)}\}_{i=1}^n\) from Phase B Step 1.


Receiver computes, for each \(i\):
\[
\widetilde{h}_i^{(0)} := \left(h_{\pi(i)}^{(0)}\right)^s
\]


Receiver sends:
\[
\{\widetilde{h}_i^{(0)}\}_{i=1}^n
\]
to Sender.


#### Step 3.2 Batched aggregate equality target (public-to-Sender side)


Sender computes the public aggregate:
\[
L_c := \prod_{j=1}^n \left(h_j^{(0)}\right)^{c^j}
\]


If \(\widetilde{h}_i^{(0)} = (h_{\pi(i)}^{(0)})^s\) and \(\beta_i = c^{\pi(i)}/s\), then:
\[
\prod_{i=1}^n \left(\widetilde{h}_i^{(0)}\right)^{\beta_i}
=
\prod_{j=1}^n \left(h_j^{(0)}\right)^{c^j}
= L_c
\]


So it is enough to prove that the Receiver-claimed aggregate
\[
R_c := \prod_{i=1}^n \left(\widetilde{h}_i^{(0)}\right)^{\beta_i}
\]
is correctly formed from the authenticated exponents \(\beta_i\), and then check \(R_c=L_c\).


#### Step 3.3 Receiver proves correct multiexponentiation using authenticated \(\beta_i\)


Assume \(\beta_i\) are Receiver-owned values authenticated under \(\Delta_0\), i.e. Receiver has \((\beta_i,u_{\beta_i})\) and Sender has \(v_{\beta_i}\) with:
\[
v_{\beta_i} = \Delta_0 \beta_i - u_{\beta_i}
\]


Receiver computes and sends:
\[
R_c := \prod_{i=1}^n \left(\widetilde{h}_i^{(0)}\right)^{\beta_i}
\]
\[
U_c := \prod_{i=1}^n \left(\widetilde{h}_i^{(0)}\right)^{u_{\beta_i}}
\]


Sender computes:
\[
V_c := \prod_{i=1}^n \left(\widetilde{h}_i^{(0)}\right)^{v_{\beta_i}}
\]


Sender checks:
\[
R_c^{\Delta_0} \stackrel{?}= U_c \cdot V_c
\]


If the check fails, abort.


This proves (batched, under DLOG hardness and auth soundness) that \(R_c\) is consistent with the authenticated exponents \(\beta_i\).


#### Step 3.4 Sender checks aggregate equality


Sender checks:
\[
R_c \stackrel{?}= L_c
\]


If the check fails, abort.


If the checks pass, Sender accepts the first masked shuffled batch \(\{\widetilde{h}_i^{(0)}\}\) as correct (up to batching/challenge soundness).


---


### Phase B — Step 4. Receiver sends second masked shuffled batch and proves correctness


This step handles the Receiver-owned exponent shares and proves correctness of:
\[
\widetilde{h}_i^{(1)} = g_{\pi(i)}^{x_{\pi(i)}^1 s} = g_{\pi(i)}^{\gamma_i}
\]
without revealing \(\pi\).

(The actual send of \(\{\widetilde{h}_i^{(1)}\}_{i=1}^n\) is performed in Step 4.1 below.)


#### Step 4.1 Receiver computes and sends second masked shuffled batch


For each \(i\), Receiver computes:
\[
\widetilde{h}_i^{(1)} := g_{\pi(i)}^{\gamma_i}
\quad\text{where } \gamma_i = x_{\pi(i)}^1 s.
\]


Receiver sends:
\[
\{\widetilde{h}_i^{(1)}\}_{i=1}^n
\]
to Sender.


#### Step 4.2 Aggregate target induced by \(\beta_i = c^{\pi(i)}/s\)


Recall from Phase B Step 2:
\[
\beta_i = \frac{c^{\pi(i)}}{s}
\qquad\text{and}\qquad
\gamma_i = x_{\pi(i)}^1 s.
\]


If \(\widetilde{h}_i^{(1)} = g_{\pi(i)}^{\gamma_i}\), then
\[
\prod_{i=1}^n \left(\widetilde{h}_i^{(1)}\right)^{\beta_i}
=
\prod_{i=1}^n g_{\pi(i)}^{\gamma_i \beta_i}
=
\prod_{i=1}^n g_{\pi(i)}^{x_{\pi(i)}^1 c^{\pi(i)}}
=
\prod_{j=1}^n g_j^{x_j^1 c^j}.
\]


So the proof reduces to showing equality of two aggregates:


- **Shuffled-side aggregate** (from sent group elements and authenticated \(\beta_i\))
- **Reference aggregate** (from public bases \(g_i\) and authenticated Receiver shares \(x_i^1\))


#### Step 4.3 Receiver proves the shuffled-side aggregate is correctly formed from authenticated \(\beta_i\)


Define the shuffled-side aggregate:
\[
R_c^{(1)} := \prod_{i=1}^n \left(\widetilde{h}_i^{(1)}\right)^{\beta_i}.
\]


Assume \(\beta_i\) are Receiver-owned values authenticated under \(\Delta_0\), i.e. Receiver has \((\beta_i,u_{\beta_i})\) and Sender has \(v_{\beta_i}\) with:
\[
v_{\beta_i} = \Delta_0 \beta_i - u_{\beta_i}.
\]


Receiver computes and sends:
\[
R_c^{(1)} := \prod_{i=1}^n \left(\widetilde{h}_i^{(1)}\right)^{\beta_i}
\]
\[
U_{\beta}^{(1)} := \prod_{i=1}^n \left(\widetilde{h}_i^{(1)}\right)^{u_{\beta_i}}
\]


Sender computes:
\[
V_{\beta}^{(1)} := \prod_{i=1}^n \left(\widetilde{h}_i^{(1)}\right)^{v_{\beta_i}}
\]


Sender checks:
\[
\left(R_c^{(1)}\right)^{\Delta_0} \stackrel{?}= U_{\beta}^{(1)} \cdot V_{\beta}^{(1)}.
\]


If the check fails, abort.


This proves that \(R_c^{(1)}\) is consistent with the authenticated exponents \(\beta_i\) (batched, under DLOG hardness and auth soundness).


#### Step 4.4 Receiver proves the reference aggregate is correctly formed from authenticated \(x_i^1\)


Define the reference aggregate:
\[
Q_c^{(1)} := \prod_{i=1}^n g_i^{c^i x_i^1}.
\]


Receiver-owned shares \(x_i^1\) are already authenticated under \(\Delta_0\):
- Receiver has \((x_i^1, u_{x_i}^1)\)
- Sender has \(v_{x_i}^1\)


with:
\[
v_{x_i}^1 = \Delta_0 x_i^1 - u_{x_i}^1.
\]


Receiver computes and sends:
\[
Q_c^{(1)} := \prod_{i=1}^n g_i^{c^i x_i^1}
\]
\[
U_x^{(1)} := \prod_{i=1}^n g_i^{c^i u_{x_i}^1}
\]


Sender computes:
\[
V_x^{(1)} := \prod_{i=1}^n g_i^{c^i v_{x_i}^1}
\]


Sender checks:
\[
\left(Q_c^{(1)}\right)^{\Delta_0} \stackrel{?}= U_x^{(1)} \cdot V_x^{(1)}.
\]


If the check fails, abort.


This proves that \(Q_c^{(1)}\) is consistent with the authenticated Receiver shares \(x_i^1\) (batched, under DLOG hardness and auth soundness).


#### Step 4.5 Sender checks aggregate equality


Sender checks:
\[
R_c^{(1)} \stackrel{?}= Q_c^{(1)}.
\]


If the check fails, abort.


If the checks pass, Sender accepts the second masked shuffled batch \(\{\widetilde{h}_i^{(1)}\}\) as correct (up to batching/challenge soundness).


#### Summary of Step 4 proof logic


This step proves correctness of the sent \(\widetilde{h}_i^{(1)}\) list by showing:
\[
\prod_i (\widetilde{h}_i^{(1)})^{\beta_i}
=
\prod_i g_i^{c^i x_i^1},
\]
where:
- left side is tied to the sent group elements and authenticated \(\beta_i=c^{\pi(i)}/s\),
- right side is tied to the authenticated Receiver shares \(x_i^1\),
- and the scalar-side consistency of \(\beta_i,\gamma_i,\pi(i),s\) was already enforced in Phase B Step 2.4.


---


### Phase B — Step 5 (final). Receiver unmasks the shuffled outputs using authenticated \(\sigma = 1/s\)


At this point, Sender and Receiver can combine the two masked shuffled batches to obtain the masked shuffled outputs:
\[
M_i := \widetilde{h}_i^{(0)} \cdot \widetilde{h}_i^{(1)}
= g_{\pi(i)}^{x_{\pi(i)}^0 s} \cdot g_{\pi(i)}^{x_{\pi(i)}^1 s}
= g_{\pi(i)}^{x_{\pi(i)} s}
\]


The goal of this step is to unmask \(s\) without revealing \(s\) (or \(\sigma=1/s\)).


Receiver uses the authenticated one-sided value \(\sigma = 1/s\) (under \(\Delta_0\)) to send:
\[
T_i := M_i^\sigma = g_{\pi(i)}^{x_{\pi(i)}}
\]


#### Step 5.1 Receiver computes and sends final outputs plus proof auxiliaries


Assume \(\sigma\) is Receiver-owned and authenticated under \(\Delta_0\):
- Receiver holds \((\sigma, u_\sigma)\)
- Sender holds \(v_\sigma\)


with:
\[
v_\sigma = \Delta_0 \sigma - u_\sigma
\]


For each \(i\), Receiver computes:
\[
T_i := M_i^\sigma
\]
\[
K_i := M_i^{u_\sigma}
\]


Receiver sends to Sender:
\[
\{T_i\}_{i=1}^n,\quad \{K_i\}_{i=1}^n
\]


#### Step 5.2 Batched proof of correct unmasking exponent


Both parties derive fresh batching coefficients:
\[
\rho_1,\dots,\rho_n \in \mathbb{F}_q
\]
(from a fresh shared seed / transcript challenge)


Define:
\[
T_\rho := \prod_{i=1}^n T_i^{\rho_i}
\]
\[
K_\rho := \prod_{i=1}^n K_i^{\rho_i}
\]
\[
M_\rho := \prod_{i=1}^n M_i^{\rho_i}
\]


Sender checks:
\[
T_\rho^{\Delta_0} \stackrel{?}= K_\rho \cdot M_\rho^{v_\sigma}
\]


If the check fails, abort.


This proves (batched, under DLOG hardness and auth soundness) that the sent \(T_i\) are correctly exponentiated using the same authenticated \(\sigma=1/s\).


#### Step 5.3 Final outputs


If the batched check passes, Sender accepts:
\[
T_i = g_{\pi(i)}^{x_{\pi(i)}} \quad \text{for } i=1,\dots,n
\]


Receiver also has the same outputs locally.


This completes Phase B.


---


### Phase B challenge ordering note (important)


For soundness, use the following order (exact transcript binding can be specified later):


1. Receiver commits/authenticates \(\pi\), \(s\), \(\sigma=1/s\)
2. Challenge \(c\) is sampled/fixed
3. Receiver authenticates \(\beta_i = c^{\pi(i)}/s\) and \(\gamma_i=x_{\pi(i)}^1 s\)
4. Sender samples \(p,q,r,t\) for the extended product consistency check
5. Receiver sends \(\widetilde{h}_i^{(0)}\), \(\widetilde{h}_i^{(1)}\)
6. Batched multiexp / aggregate equality checks run
7. Receiver sends final unmasked outputs and unmasking proof


---


## 8. Integration Back to DY-OPRF (Phase A -> Phase B)


Instantiate Phase B with:
- public bases:
  \[
  g_i := g^{r_i}
  \]
- exponents (rename to avoid symbol collision with original Sender inputs):
  \[
  e_i := b_i = \frac{1}{r_i(x_i+k)}
  \]


Then:
\[
g_i^{e_i}
=
(g^{r_i})^{1/(r_i(x_i+k))}
=
g^{1/(x_i+k)}
\]


After Phase B outputs \(g_{\pi(i)}^{e_{\pi(i)}}\), this equals the desired shuffled DY-OPRF outputs:
\[
g^{1/(x_{\pi(i)}+k)}.
\]


---


## 9. Remaining TODOs (to finalize for Codex implementation)


1. **Exact BeDOZa/VOLE routines**
   - concrete transcript/message formats for one-sided auth and full share auth
   - batched opening procedures and MAC-check details


2. **Wolverine backend linear check**
   - exact protocol transcript for checking \(L=\Delta\lambda+\mu\) without revealing \(\Delta\)
   - challenge generation / transcript binding


3. **Challenge derivation conventions**
   - domain-separated transcript labels for all challenge seeds and field coefficients


4. **Abort/retry policy**
   - zero denominators in Phase A
   - malformed permutation values
   - duplicate/out-of-range permutation handling (if not fully enforced elsewhere)