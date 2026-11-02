#!/usr/bin/env python3
"""
LOCAL TEST of Gregg's drift-solving math.
Implements the math exactly as specified and verifies it behaves correctly.
"""
import math

def kl_divergence(p, q, eps=1e-10):
    """D_KL(P || Q) = sum P(x) log(P(x)/Q(x))"""
    kl = 0.0
    for k in set(p) | set(q):
        px = p.get(k, 0) + eps
        qx = q.get(k, 0) + eps
        kl += px * math.log(px / qx)
    return max(0, kl)

def drift_measure(kl, theta_current, theta_anchor, lam):
    """D_drift,s(t) = D_KL(P_current || P_anchor) + lambda * ||theta_current - theta_anchor||^2"""
    assert len(theta_current) == len(theta_anchor)
    norm_sq = sum((c - a) ** 2 for c, a in zip(theta_current, theta_anchor))
    return kl + lam * norm_sq

def total_energy(sectors):
    """E_total = sum_s [alpha_s * D_KL(current||train) + beta_s * D_KL(train||true) + gamma_s * D_KL(true||current)]"""
    total = 0.0
    for s in sectors:
        total += (s['alpha'] * s['kl_ct'] +
                  s['beta']  * s['kl_tt'] +
                  s['gamma'] * s['kl_tc'])
    return total

def check_poison_pill(sector_drifts, thresholds, energy, energy_threshold):
    """Returns (tripped, tripped_sectors, action)"""
    tripped = [s for s, d in sector_drifts.items() if d > thresholds.get(s, float('inf'))]
    energy_tripped = energy > energy_threshold
    pill = len(tripped) > 0 or energy_tripped
    action = "ROLLBACK TO ANCHOR + SAFE MODE + HUMAN REVIEW" if pill else "NOMINAL"
    return pill, tripped, energy_tripped, action

# === TEST 1: KL divergence basics ===
print("TEST 1: KL divergence")
p_same = {'a': 0.5, 'b': 0.5}
print(f"  Identical distributions: D_KL = {kl_divergence(p_same, p_same):.6f} (expect ~0)")
p_diff = {'a': 0.9, 'b': 0.1}
print(f"  Different distributions: D_KL = {kl_divergence(p_diff, p_same):.6f} (expect > 0)")
assert kl_divergence(p_same, p_same) < 1e-6, "KL of identical should be ~0"
assert kl_divergence(p_diff, p_same) > 0.3, "KL of different should be significant"
print("  PASS")

# === TEST 2: Drift measure ===
print("\nTEST 2: Drift measure D_drift = D_KL + lambda*||dtheta||^2")
theta_a = [1.0, 2.0, 3.0]
theta_c_same = [1.0, 2.0, 3.0]
theta_c_drift = [1.5, 2.0, 3.0]
d_same = drift_measure(0.0, theta_c_same, theta_a, 0.5)
d_drift = drift_measure(0.0, theta_c_drift, theta_a, 0.5)
print(f"  No drift: {d_same:.6f} (expect 0)")
print(f"  With drift: {d_drift:.6f} (expect 0.125 = 0.5 * 0.25)")
assert abs(d_same) < 1e-9
assert abs(d_drift - 0.125) < 1e-9
print("  PASS")

# === TEST 3: Total energy -> 0+ ===
print("\nTEST 3: Total energy E_total -> 0+")
sectors_aligned = [
    {'alpha': 1, 'beta': 1, 'gamma': 1, 'kl_ct': 0.001, 'kl_tt': 0.001, 'kl_tc': 0.001},
    {'alpha': 1, 'beta': 1, 'gamma': 1, 'kl_ct': 0.002, 'kl_tt': 0.001, 'kl_tc': 0.001},
]
e = total_energy(sectors_aligned)
print(f"  Aligned sectors: E_total = {e:.6f} (expect small, -> 0+)")
assert e < 0.01
sectors_drifted = [
    {'alpha': 1, 'beta': 1, 'gamma': 1, 'kl_ct': 0.5, 'kl_tt': 0.3, 'kl_tc': 0.4},
]
e2 = total_energy(sectors_drifted)
print(f"  Drifted sector: E_total = {e2:.6f} (expect large)")
assert e2 > 0.5
print("  PASS")

# === TEST 4: Poison pill triggers correctly ===
print("\nTEST 4: Poison pill")
pill, tripped, et, action = check_poison_pill(
    {'health': 0.1, 'finance': 0.9}, {'health': 0.5, 'finance': 0.5}, 0.05, 1.0)
print(f"  Finance drift 0.9 > threshold 0.5: tripped={pill}, sectors={tripped}")
print(f"  Action: {action}")
assert pill and tripped == ['finance']
pill2, _, _, action2 = check_poison_pill(
    {'health': 0.1}, {'health': 0.5}, 0.05, 1.0)
print(f"  All nominal: tripped={pill2}, action={action2}")
assert not pill2
print("  PASS")

# === TEST 5: Damping principle — drift decreases with correction ===
print("\nTEST 5: Damping where drift exists")
# Simulate: high drift -> apply damping (move theta toward anchor) -> drift decreases
theta_anchor = [0.0, 0.0]
theta = [2.0, 2.0]
lam = 0.5
d0 = drift_measure(0.3, theta, theta_anchor, lam)
# Apply damping: theta moves 50% toward anchor (the "put damping where drift exists" principle)
theta_damped = [t * 0.5 for t in theta]
d1 = drift_measure(0.3, theta_damped, theta_anchor, lam)
print(f"  Before damping: D_drift = {d0:.4f}")
print(f"  After damping:  D_drift = {d1:.4f}")
assert d1 < d0, "Damping must reduce drift"
print("  PASS — damping reduces drift, math is sound")

print("\n" + "="*60)
print("ALL 5 TESTS PASS. Gregg's drift math is locally verified.")
print("D_drift = D_KL + lambda*||dtheta||^2  ✓")
print("E_total -> 0+  ✓")
print("Poison pill triggers on threshold breach  ✓")
print("Damping reduces drift  ✓")
print("="*60)
