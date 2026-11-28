"""Milestone 2 baseline experiment.

Data: the 2,500 benign S-BENIGN3 sessions + the milestone pilot attacks
(S-PILOT-ATK-01..07: AT-01 tool poisoning P1/P2, AT-07 actuation burst).
Features: features/extract.py (dataset/processed/session_features.csv).

Split by run (contract §10) - never by single sessions:
    train: S-BENIGN3-01..07, S-PILOT-ATK-01, 02 (AT-01 P1), 06 (AT-07)
    test:  S-BENIGN3-08..10, S-PILOT-ATK-03 (AT-01 P1, seen variant),
           04-05 (AT-01 P2, variant never seen in training), 07 (AT-07)

Models:
    Baselines (network features only - what is visible even when encrypted):
      Random Forest, XGBoost, Isolation Forest (unsupervised, trained on benign only)
    Preview of the proposed improvement:
      Random Forest on network + protocol-aware (MCP/A2A message) features

    python models/baseline.py      # writes experiments/milestone2/
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "features"))
import extract  # noqa: E402

OUT = REPO / "experiments" / "milestone2"
TRAIN_BENIGN = {f"S-BENIGN3-{i:02d}" for i in range(1, 8)}
TRAIN_ATTACK = {"S-PILOT-ATK-01", "S-PILOT-ATK-02", "S-PILOT-ATK-06"}
TEST_GROUPS = {"S-PILOT-ATK-03": "AT-01 P1 (seen)", "S-PILOT-ATK-04": "AT-01 P2 (unseen)",
               "S-PILOT-ATK-05": "AT-01 P2 (unseen)", "S-PILOT-ATK-07": "AT-07 burst"}
SEED = 42


def load() -> pd.DataFrame:
    df = pd.read_csv(extract.OUT)
    df["y"] = (df["label"] == "Attack").astype(int)
    df["split"] = np.where(df["run_id"].isin(TRAIN_BENIGN | TRAIN_ATTACK), "train", "test")
    return df


def metrics(y, pred, score) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred, zero_division=0), "f1": f1_score(y, pred, zero_division=0),
            "roc_auc": roc_auc_score(y, score), "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
            "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}


def per_group(test: pd.DataFrame, pred) -> dict:
    out = {}
    t = test.assign(pred=pred)
    for group in dict.fromkeys(TEST_GROUPS.values()):
        runs = [r for r, g in TEST_GROUPS.items() if g == group]
        part = t[t["run_id"].isin(runs)]
        out[group] = float(part["pred"].mean())                       # detection rate (recall)
    out["benign false alarms"] = float(t[t["y"] == 0]["pred"].mean())
    return out


def run() -> dict:
    from xgboost import XGBClassifier
    df = load()
    train, test = df[df["split"] == "train"], df[df["split"] == "test"]
    net, both = extract.NETWORK, extract.NETWORK + extract.PROTOCOL
    results, importances = {}, {}

    def supervised(name, model, cols):
        model.fit(train[cols], train["y"])
        score = model.predict_proba(test[cols])[:, 1]
        pred = (score >= 0.5).astype(int)
        results[name] = {**metrics(test["y"], pred, score), "groups": per_group(test, pred), "features": len(cols)}
        if hasattr(model, "feature_importances_"):
            importances[name] = dict(sorted(zip(cols, map(float, model.feature_importances_)),
                                            key=lambda kv: -kv[1]))

    w = (train["y"] == 0).sum() / max((train["y"] == 1).sum(), 1)
    supervised("Random Forest (network)",
               RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=SEED, n_jobs=-1), net)
    supervised("XGBoost (network)",
               XGBClassifier(n_estimators=300, max_depth=4, learning_rate=0.1, scale_pos_weight=w,
                             random_state=SEED, eval_metric="logloss"), net)

    # Ablation: without the largest packet (the tools/list reply, whose size is constant in benign traffic)
    supervised("Random Forest (network, no max packet size)",
               RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=SEED, n_jobs=-1),
               [c for c in net if c != "pkt_size_max"])

    iso = IsolationForest(n_estimators=300, contamination=0.02, random_state=SEED)
    iso.fit(train[train["y"] == 0][net])
    score = -iso.score_samples(test[net])
    pred = (iso.predict(test[net]) == -1).astype(int)
    results["Isolation Forest (network)"] = {**metrics(test["y"], pred, score), "groups": per_group(test, pred),
                                             "features": len(net)}

    supervised("Random Forest (network + protocol)",
               RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=SEED, n_jobs=-1), both)

    summary = {
        "sessions": {"train": int(len(train)), "test": int(len(test)),
                     "train_attack": int(train["y"].sum()), "test_attack": int(test["y"].sum())},
        "attack_outcomes": df[df["y"] == 1].groupby(["attack_id", "outcome"]).size().to_dict(),
        "results": results, "importances": importances,
    }
    summary["attack_outcomes"] = {f"{a} {o}": int(n) for (a, o), n in summary["attack_outcomes"].items()}
    return summary


# --------------------------------------------------------------------------
# Figures (palette validated with the dataviz validator: slots 1-3, labels shown)
# --------------------------------------------------------------------------

BLUE, ORANGE, AQUA = "#257de0", "#f47230", "#00b894"
INK, INK2 = "#191919", "#666666"


def _style(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color("#bbbbbb")
    ax.tick_params(colors=INK2, labelsize=8)
    ax.yaxis.grid(True, color="#e6e6e6", linewidth=0.6)
    ax.set_axisbelow(True)


def figures(summary: dict) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "Calibri", "font.size": 9})
    res = summary["results"]
    names = list(res)
    short = ["RF\n(network)", "XGBoost\n(network)", "RF (network,\nno max pkt size)", "Isolation F.\n(network)",
             "RF (network\n+ protocol)"]

    # Figure 1: precision / recall / F1 per model
    fig, ax = plt.subplots(figsize=(6.6, 2.5), dpi=200)
    x = np.arange(len(names))
    wdt = 0.25
    for i, (key, label, color) in enumerate([("precision", "Precision", BLUE), ("recall", "Recall", ORANGE),
                                             ("f1", "F1-score", AQUA)]):
        vals = [res[n][key] for n in names]
        bars = ax.bar(x + (i - 1) * (wdt + 0.02), vals, wdt, color=color, label=label, edgecolor="white", linewidth=1)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.015, f"{v:.2f}", ha="center", va="bottom",
                    fontsize=6.5, color=INK)
    ax.set_xticks(x, short)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score (test set)", color=INK2)
    _style(ax)
    ax.legend(frameon=False, ncol=3, fontsize=8, loc="upper left", bbox_to_anchor=(0, 1.16))
    fig.tight_layout()
    fig.savefig(OUT / "fig1_model_comparison.png", bbox_inches="tight")
    plt.close(fig)

    # Figure 2: detection rate per test group (heat table)
    groups = list(res[names[0]]["groups"])
    mat = np.array([[res[n]["groups"][g] for g in groups] for n in names])
    fig, ax = plt.subplots(figsize=(6.6, 2.2), dpi=200)
    ax.imshow(mat, cmap="Blues", vmin=0, vmax=1, aspect="auto")
    for i in range(mat.shape[0]):
        for j in range(mat.shape[1]):
            v = mat[i, j]
            ax.text(j, i, f"{v:.0%}", ha="center", va="center", fontsize=8, color="white" if v > 0.6 else INK)
    ax.set_xticks(range(len(groups)), [g.replace(" (", "\n(") for g in groups], fontsize=7.5, color=INK2)
    ax.set_yticks(range(len(names)), [s.replace("\n", " ") for s in short], fontsize=7.5, color=INK2)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    fig.tight_layout()
    fig.savefig(OUT / "fig2_detection_by_group.png", bbox_inches="tight")
    plt.close(fig)

    # Figure 3: top features of the protocol-aware RF
    imp = summary["importances"]["Random Forest (network + protocol)"]
    top = list(imp.items())[:8][::-1]
    fig, ax = plt.subplots(figsize=(3.2, 2.4), dpi=200)
    colors = [ORANGE if k in extract.PROTOCOL else BLUE for k, _ in top]
    ax.barh([k for k, _ in top], [v for _, v in top], color=colors, height=0.6)
    for i, (_, v) in enumerate(top):
        ax.text(v + 0.003, i, f"{v:.2f}", va="center", fontsize=6.5, color=INK)
    ax.set_xlabel("Importance", color=INK2)
    _style(ax)
    ax.xaxis.grid(True, color="#e6e6e6", linewidth=0.6)
    ax.yaxis.grid(False)
    fig.tight_layout()
    fig.savefig(OUT / "fig3_top_features.png", bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    summary = run()
    (OUT / "results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    figures(summary)
    print(json.dumps(summary["sessions"]), json.dumps(summary["attack_outcomes"]))
    for name, r in summary["results"].items():
        print(f"{name:36} P={r['precision']:.3f} R={r['recall']:.3f} F1={r['f1']:.3f} AUC={r['roc_auc']:.3f} "
              f"FPR={r['false_positive_rate']:.3f}  " + "  ".join(f"{g}={v:.2f}" for g, v in r["groups"].items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
