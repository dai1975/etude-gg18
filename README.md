# gg18-etude

# GG18
R. Gennaro and S. Goldfeder. Fast Multiparty Threshold ECDSA with Fast Trustless Setup. In ACM CCS 2018.

4.1 Key generation protocol
Phase 1. Each Player Pi selects ui. Pi send g^ui to Pj(i!=j) by using commitment schema.
Phase 2. All Players perform Join-Feldman VSS together.
Phase 3. ZK-prove.

At the end of the KeyGen,
* Each player `Pi` secretly hold:
  - Localy generated secret value `ui`
  - `Pj`'s Feldman share value `sij`, and those summary `si = Σ j(sij)`
  - Joint Feldman Shamir's secret share value `xi = si`
* All player knows:
  - `g^ui`
  - Joint Feldman Shamir's public key `y = g^x = g^Σ ui = Π g^ui`
* No any player knows:
  - Joint Feldman Shamir's secret key `x = Σ ui`


4.2 Signature Generation

Phase 0. Convert (t,n) share xi to (t',t') share of wi
Phase 1. Each player `Pi` selects `ki`,`γ i`
         Define `k = Σ ki, γ =Σ γ i`
         Each player broadcast g^γ i by using commitment scheme.
Phase 2.
 2-a. Every pair of Pi and Pj performs MtA against `ki` and `γ j` then get `α i` and `β j`.
      Note that `ki * γ j = α ij + β ij`.
      Each player `Pi` compute `δ i = ki * γ i + Σ j!=i(α ij + β ji).
      Note that `k*γ  = Σ δ i`
 2-b. MtA agains `ki` and `wi` then get `μ ij` and `ν ij`
      As is 2-a, Pi compute `σ i = ki*wi + Σ j!=i(μ ij + ν ji)`, note `k*x = Σ σ i`

Phase 3. Each player `Pi` broadcasts `δ i` and all players are compute δ  = Σ δ i = k*γ

Phase 4. Each player `Pi` opens `g^γ i` and compute `R = (Π g^γ i)^(1/δ ) = g^(1/k)` and `r = H(R)`

Phase 5. Each player `Pi` compute `si = m*ki + r*σ i`
         Note that `Σ si = mΣ ki + rΣ σ  = mk + rkx = k(m+xr) = s`


Verify:
  1. Each Player broadcast `g^wi` and calc `y = Π g^wi = g^(Σ wi) = g^x`
  2. Test `g^(m/s) + y * (r/s) = R`
     Note that `g^(m/s) + y ^ (r/s) = g^(m/s) + g^(x * (r/s)) = g^((m+rx)/s) = g^(1/k) = R`

# software design of this etude

To the protocol be simple, I start followint conditions:
 a. Skip DKG. Each Player generate ui and treat the sum is secret.
 b. threshold `t = n-1`, so `wi == ui`.

 
