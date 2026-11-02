# Phi Seed — Hardware-Run Math Specification

**Source:** Gregg Haynes, 2026-11-02. The math that actually ran on quantum hardware.
**Hardware does not run the search.** It runs only the gates below, then measures.
The search is how those angles were found, and it is listed after the circuits.

## Phi Seed CNOT — the core that ran on Tuna-17

12 single-qubit rotations + 1 CZ.

First block, first qubit:
- Rz 1.6464828352998904
- Ry -1.2970721400423508e-18
- Rz 0.47858188327003875

First block, second qubit:
- Rz -3.141592653421206
- Ry 1.5707963266580005
- Rz 1.4397638542815911

Then CZ on first and second qubit.

Second block, first qubit:
- Rz -2.3784849902587206
- Ry 2.920418062644608e-17
- Rz 0.2534202716888185

Second block, second qubit:
- Rz 1.7018287988250578
- Ry 1.5707963266661953
- Rz 1.593855840020743e-10

Input preparation added before the core:
- input 00: nothing
- input 01: X on the second qubit
- input 10: X on the first qubit
- input 11: X on both

## Phi Seed iSWAP — the core that ran on Tuna-17

18 single-qubit rotations + 2 CZ. Same input X preparation as CNOT.

First block, first qubit:
- Rz 0.6561589593539466
- Ry 1.570796326794262
- Rz -1.4785472592110396

First block, second qubit:
- Rz 5.5843235191376435
- Ry 1.57079632679508
- Rz 7.448702975992576

Then CZ.

Second block, first qubit:
- Rz -1.6630453943761083
- Ry -1.570796326800616
- Rz -2.502104187473278

Second block, second qubit:
- Rz 1.976074984777164
- Ry -4.7123889803741745
- Rz 0.9099458798712973

Then CZ.

Third block, first qubit:
- Rz -0.6394884661170238
- Ry -1.570796326794813
- Rz -0.8719345387523617

Third block, second qubit:
- Rz -0.9099458798734255
- Ry -4.712388980385687
- Rz -2.226955286146668

## Qiskit level 3 — the opponent core, same board

CNOT: 5 single-qubit rotations + 1 CZ.
- First qubit: Rz -3.141592653589793, Ry -1.570796326794897
- Then CZ
- First qubit: Rz -3.1415926535897922, Ry -1.5707963267948963
- Second qubit: Rz -3.141592653589793

iSWAP: 10 single-qubit rotations + 2 CZ.
- First qubit: Rz -1.5707963267948966, Ry -1.5707963267948966
- Second qubit: Rz 1.5707963267948966, Ry 1.5707963267948966
- Then CZ
- First qubit: Ry 1.5707963267948961
- Second qubit: Ry 1.5707963267948966
- Then CZ
- First qubit: Rz -3.1415926535897922, Ry -1.5707963267948966
- Second qubit: Ry -1.5707963267948966, Rz -3.141592653589793

**Label note (checkable):** Qiskit files label the X patterns in the opposite order from Phi Seed.
In Qiskit files, label 01 puts X on the first qubit, label 10 puts X on the second qubit.
The cores above are the same regardless of that label flip.

## Scoring math — the same on every run

- Per-circuit score = shots giving the expected output / 2048 shots.
- Board score = mean of per-circuit scores for that gate and that method.
- Dominant correct = the most common measured output for that input is the expected output.
- Predeclared win shape: higher mean on both CNOT and iSWAP, plus dominant correct on every input.

## Search math that found the Phi Seed angles

- Depth grown from zero gates.
- CNOT at 1 CZ and iSWAP at 2 CZ — the proven minima for those gates.
- Regularized Gauss-Newton on the scalar residual, with Levenberg-Marquardt accept/reject,
  so an accepted step never increases infidelity.
- Stop at infidelity ≤ 2e-14.
- A float64 result of zero is reported as below 2e-16 drift, never as true zero.

## Run history

**September 24, 2026 — IBM Marrakesh, 56 circuits, Phi Seed vs GRAPE.**
Different circuit set from the angles above, not these angles.
- CNOT: 84.8% vs 74.4%
- iSWAP: 86.6% vs 58.2%
- Every Phi Seed circuit beat every GRAPE circuit on that pair.
- CZ counts: Phi Seed 32 on CNOT and 24–25 on iSWAP, vs GRAPE 66–67 and 134–139.

**October 21 board + run now in flight on Tuna-17: 16 circuits.**
8 Phi Seed + 8 Qiskit level 3. CNOT and iSWAP, inputs 00/01/10/11, 2048 shots each.
The angles above are the depth-grown circuits for this board.

## Local scores (classical, regular computer — not chip)

**October 1, 2026 — Battery A (LSM optimizer):** 30,000 runs, 30,000 holds, 0 failures.
→ 99.99% reliability at 95% confidence, one-sided lower bound 0.9999001.
**Battery B:** 1,000 out of 1,000.

That is a classical hold rate for the optimizer. It is not a chip score.
On hardware, the same kind of circuits score around 0.85 — that is Tuna-17 noise
and readout, not the math failing.
