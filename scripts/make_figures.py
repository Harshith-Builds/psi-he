"""Turn results/{A,B,C}.json into figures and a Markdown summary.

Usage: python3 scripts/make_figures.py results
"""
import json
import math
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

R = sys.argv[1] if len(sys.argv) > 1 else "results"
SETS = [s for s in ("C", "A", "B") if os.path.exists(os.path.join(R, s + ".json"))]
D = {s: json.load(open(os.path.join(R, s + ".json"))) for s in SETS}
LABEL = {s: f"Set {s}\n|S|=$2^{{{int(math.log2(D[s]['server_size']))}}}$, "
            f"{D[s]['params']['partitions']}x{D[s]['params']['degree']}" for s in SETS}
COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#6250d6"]  # categorical slots 1-5, 7

GROUPS = [  # (legend label, keys in online_median_s)
    ("OPRF round (both)", ["client_oprf_blind", "server_oprf_eval_prove", "client_oprf_verify_unblind"]),
    ("Client: cuckoo + encrypt", ["client_cuckoo", "client_encrypt_query"]),
    ("Server: query powers", ["server_powers"]),
    ("Server: masked coeffs + poly eval", ["server_encode_masked_coeffs", "server_poly_eval"]),
    ("Server: (de)serialize, switch, flood", ["server_deserialize", "server_switch_flood", "server_serialize"]),
    ("Client: decrypt + decode", ["client_decrypt_decode"]),
]


def style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color("#999999")
    ax.spines["bottom"].set_color("#999999")
    ax.tick_params(colors="#52514e", labelsize=8)


# ---------------------------------------------------------------- figure 1: online time breakdown
fig, ax = plt.subplots(figsize=(7.2, 2.9), dpi=200)
y = list(range(len(SETS)))
left = [0.0] * len(SETS)
for gi, (name, keys) in enumerate(GROUPS):
    vals = [sum(D[s]["online_median_s"].get(k, 0) for k in keys) for s in SETS]
    ax.barh(y, vals, left=left, color=COLORS[gi], height=0.55, label=name, edgecolor="white", linewidth=1)
    left = [l + v for l, v in zip(left, vals)]
for yi, s in zip(y, SETS):
    ax.text(left[yi] + 0.08, yi, f"{D[s]['online_median_s']['online_total']:.2f} s", va="center", fontsize=8,
            color="#0b0b0b")
ax.set_yticks(y, [LABEL[s] for s in SETS], fontsize=8)
ax.set_xlabel("Online time per query, median of trials (s), 2 CPU cores", fontsize=8, color="#52514e")
ax.grid(axis="x", color="#e6e6e6", lw=0.8)
ax.set_axisbelow(True)
ax.set_xlim(0, max(left) * 1.15)
style(ax)
ax.legend(frameon=False, fontsize=7, ncol=3, loc="upper center", bbox_to_anchor=(0.45, -0.28))
fig.tight_layout()
fig.savefig(os.path.join(R, "fig_online_breakdown.png"), bbox_inches="tight")

# ---------------------------------------------------------------- figure 2: communication vs baselines
cats = ["Plaintext\nbaseline", "SHA-256\nbaseline"] + [LABEL[s] for s in SETS]
any_s = D[SETS[0]]
up = [any_s["baseline_plain"]["upload_B"], any_s["baseline_sha256"]["upload_B"]]
down = [any_s["baseline_plain"]["download_B"], any_s["baseline_sha256"]["download_B"]]
for s in SETS:
    z = D[s]["sizes_B"]
    up.append(z["oprf_request"] + z["he_query"])
    down.append(z["oprf_response"] + z["he_response"])
fig, ax = plt.subplots(figsize=(7.2, 3.0), dpi=200)
w = 0.36
xs = list(range(len(cats)))
ax.bar([x - w / 2 - 0.01 for x in xs], up, w, color=COLORS[0], label="Client -> server (upload)")
ax.bar([x + w / 2 + 0.01 for x in xs], down, w, color=COLORS[1], label="Server -> client (download)")


def fmt(b):
    return f"{b / 1e6:.1f} MB" if b >= 1e6 else (f"{b / 1e3:.0f} KB" if b >= 1e3 else f"{b:.0f} B")


for x, u, d in zip(xs, up, down):
    ax.text(x - w / 2, u * 1.25, fmt(u), ha="center", fontsize=6.5, color="#0b0b0b")
    ax.text(x + w / 2, d * 1.25, fmt(d), ha="center", fontsize=6.5, color="#0b0b0b")
ax.set_yscale("log")
ax.set_ylim(50, 1e8)
ax.set_xticks(xs, cats, fontsize=7.5)
ax.set_ylabel("Bytes per query (log scale)", fontsize=8, color="#52514e")
ax.grid(axis="y", color="#e6e6e6", lw=0.8)
ax.set_axisbelow(True)
style(ax)
ax.legend(frameon=False, fontsize=7.5, loc="upper left")
fig.tight_layout()
fig.savefig(os.path.join(R, "fig_communication.png"), bbox_inches="tight")


# ---------------------------------------------------------------- summary table + bin-overflow bounds
def log2_overflow(n_balls, bins, cap):
    """log2 of union bound on Pr[some bin gets > cap of n_balls*3 insertions] (binomial tail)."""
    n, p = 3 * n_balls, 1.0 / bins
    terms = []
    for k in range(cap + 1, cap + 400):
        lg = math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1) + k * math.log(p) + (n - k) * math.log1p(-p)
        terms.append(lg)
    m = max(terms)
    tail = m + math.log(sum(math.exp(t - m) for t in terms))
    return (tail + math.log(bins)) / math.log(2)


rows = []
for s in SETS:
    d = D[s]
    p, z, o = d["params"], d["sizes_B"], d["online_median_s"]
    rows.append({
        "set": s, "S": d["server_size"], "N": p["N"], "log2Q": p["log2Q"], "max128": p["maxLog2Q_128"],
        "part": f"{p['partitions']}x{p['degree']}", "powers": p["powers"], "depth": p["multDepth"],
        "load": f"{p['max_load']}/{p['capacity']} (mean {p['mean_load']:.1f})",
        "overflow": log2_overflow(d["server_size"], p["bins"], p["capacity"]),
        "online": o["online_total"], "online_min": d["online_min_s"]["online_total"],
        "online_max": d["online_max_s"]["online_total"], "mults": o["server_ct_mults"],
        "server": sum(v for k, v in o.items() if k.startswith("server_") and k != "server_ct_mults"),
        "client": sum(v for k, v in o.items() if k.startswith("client_")),
        "up": z["oprf_request"] + z["he_query"], "down": z["oprf_response"] + z["he_response"],
        "qct": z["query_ct"], "rct": z["response_ct"], "setup": d["setup"],
        "offline": d["offline"], "noise": d["noise"], "corr": d["correctness"], "trials": d["trials"],
        "rss": d["peak_rss_MB"], "plain": d["baseline_plain"], "sha": d["baseline_sha256"],
    })
json.dump(rows, open(os.path.join(R, "summary.json"), "w"), indent=1)

L = ["# Benchmark summary", "", "| Set | \\|S\\| | N | log2 Q (max @128) | layout | powers | depth | max load | log2 Pr[overflow] |",
     "|---|---|---|---|---|---|---|---|---|"]
for r in rows:
    L.append(f"| {r['set']} | 2^{int(math.log2(r['S']))} | {r['N']} | {r['log2Q']:.0f} ({r['max128']}) | {r['part']} | "
             f"{r['powers']} | {r['depth']} | {r['load']} | {r['overflow']:.0f} |")
L += ["", "| Set | online median (min-max) s | server s | client s | ct x ct mults | upload | download | offline s | trials correct |",
      "|---|---|---|---|---|---|---|---|---|"]
for r in rows:
    L.append(f"| {r['set']} | {r['online']:.2f} ({r['online_min']:.2f}-{r['online_max']:.2f}) | {r['server']:.2f} | "
             f"{r['client']:.2f} | {r['mults']:.0f} | {fmt(r['up'])} | {fmt(r['down'])} | "
             f"{r['offline']['oprf_s'] + r['offline']['hash_interpolate_s']:.1f} | {r['corr']['trials_correct']}/{r['trials']} |")
r0 = rows[0]
L += ["", f"Plaintext baseline: {r0['plain']['median_s'] * 1e6:.0f} us per query, upload {fmt(r0['plain']['upload_B'])}.",
      f"SHA-256 baseline: {r0['sha']['median_s'] * 1e6:.0f} us per query, {r0['sha']['hashes_per_s']:.2e} hashes/s."]
open(os.path.join(R, "summary.md"), "w").write("\n".join(L) + "\n")
print("\n".join(L))
