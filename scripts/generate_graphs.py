#!/usr/bin/env python3
"""
Graph Generation Script for OS Lab Performance Evaluation
Member 3: Integration, Reporting, and Evaluation
Generates high-resolution PNG charts from measured benchmark data.
"""

import os
import sys

# Ensure writable matplotlib config directory
os.environ["MPLCONFIGDIR"] = "/tmp/mpl_cache"

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import csv

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")
GRAPHS_DIR = os.path.join(DOCS_DIR, "graphs")
CSV_PATH = os.path.join(RESULTS_DIR, "benchmark_data.csv")

os.makedirs(GRAPHS_DIR, exist_ok=True)

def load_benchmark_data():
    if not os.path.exists(CSV_PATH):
        print(f"Error: {CSV_PATH} not found. Run benchmark.py first.")
        sys.exit(1)

    components = []
    comp_means = []
    comp_stdevs = []

    scaling_sizes = []
    scaling_means = []
    scaling_stdevs = []

    repeated_trials_data = {}

    with open(CSV_PATH, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            group = row["MetricGroup"]
            if group == "RepeatedTrials":
                repeated_trials_data = {
                    "mean": float(row["MeanMs"]),
                    "median": float(row["MedianMs"]),
                    "stdev": float(row["StdevMs"]),
                    "min": float(row["MinMs"]),
                    "max": float(row["MaxMs"]),
                    "p95": float(row["p95Ms"]),
                    "trials": int(row["Trials"])
                }
            elif group == "Component":
                components.append(row["Name"])
                comp_means.append(float(row["MeanMs"]))
                comp_stdevs.append(float(row["StdevMs"]))
            elif group == "EnvScaling":
                scaling_sizes.append(int(row["Parameter"]))
                scaling_means.append(float(row["MeanMs"]))
                scaling_stdevs.append(float(row["StdevMs"]))

    return repeated_trials_data, components, comp_means, comp_stdevs, scaling_sizes, scaling_means, scaling_stdevs

def plot_component_breakdown(components, means, stdevs):
    plt.figure(figsize=(9, 5.5), dpi=300)
    colors = ["#2b5c8f", "#3a86c8", "#48bfe3", "#56cfe1", "#72efdd", "#e63946"]

    bars = plt.barh(components, means, xerr=stdevs, capsize=5, color=colors[:len(components)], edgecolor="#1d3557", alpha=0.9)

    plt.xlabel("Execution Time (milliseconds)", fontsize=11, fontweight="bold")
    plt.title("Subsystem Execution Latency Breakdown\n(OS Context: fork(), execve(), waitpid(), and proc inspection)", fontsize=12, fontweight="bold", pad=12)
    plt.grid(axis="x", linestyle="--", alpha=0.6)

    # Annotate bar values
    for bar in bars:
        width = bar.get_width()
        plt.text(width + 0.3, bar.get_y() + bar.get_height() / 2, f"{width:.2f} ms",
                 va="center", ha="left", fontsize=9, fontweight="bold")

    plt.tight_layout()
    out_path = os.path.join(GRAPHS_DIR, "benchmark_component_breakdown.png")
    plt.savefig(out_path)
    plt.close()
    print(f"[✓] Generated chart: {out_path}")

def plot_env_scaling(sizes, means, stdevs):
    plt.figure(figsize=(8.5, 5.5), dpi=300)

    plt.plot(sizes, means, marker="o", color="#2a9d8f", linewidth=2.5, markersize=7, label="Mean Latency (ms)")
    lower = [m - s for m, s in zip(means, stdevs)]
    upper = [m + s for m, s in zip(means, stdevs)]
    plt.fill_between(sizes, lower, upper, color="#2a9d8f", alpha=0.2, label="±1 Std Dev")

    for x, y in zip(sizes, means):
        plt.annotate(f"{y:.2f} ms", (x, y), textcoords="offset points", xytext=(0, 10),
                     ha="center", fontsize=9, fontweight="bold")

    plt.xlabel("Environment Variable Count (N)", fontsize=11, fontweight="bold")
    plt.ylabel("Security Scan Latency (milliseconds)", fontsize=11, fontweight="bold")
    plt.title("Security Scanner Latency vs. Environment Table Size\n(Keyword Matching O(N * M) over environ)", fontsize=12, fontweight="bold", pad=12)
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.legend(frameon=True, facecolor="white", edgecolor="#cccccc")
    plt.tight_layout()

    out_path = os.path.join(GRAPHS_DIR, "benchmark_env_scaling.png")
    plt.savefig(out_path)
    plt.close()
    print(f"[✓] Generated chart: {out_path}")

def plot_trials_distribution(trials_data):
    plt.figure(figsize=(8.5, 5), dpi=300)

    labels = ["Min", "Median", "Mean", "p95", "Max"]
    values = [
        trials_data["min"],
        trials_data["median"],
        trials_data["mean"],
        trials_data["p95"],
        trials_data["max"]
    ]
    colors = ["#457b9d", "#1d3557", "#2a9d8f", "#e76f51", "#e63946"]

    bars = plt.bar(labels, values, color=colors, width=0.55, edgecolor="#111111", alpha=0.85)

    for bar in bars:
        h = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, h + 0.3, f"{h:.2f} ms",
                 ha="center", va="bottom", fontsize=10, fontweight="bold")

    plt.ylabel("Wall-Clock Latency (milliseconds)", fontsize=11, fontweight="bold")
    plt.title(f"Full Unified Audit Trial Latency Distribution ({trials_data['trials']} Repeated Trials)\n(Mean: {trials_data['mean']:.2f} ms, Stdev: ±{trials_data['stdev']:.2f} ms)",
              fontsize=12, fontweight="bold", pad=12)
    plt.grid(axis="y", linestyle="--", alpha=0.6)
    plt.ylim(0, max(values) * 1.25)
    plt.tight_layout()

    out_path = os.path.join(GRAPHS_DIR, "benchmark_execution_time.png")
    plt.savefig(out_path)
    plt.close()
    print(f"[✓] Generated chart: {out_path}")

def main():
    trials_data, components, comp_means, comp_stdevs, scaling_sizes, scaling_means, scaling_stdevs = load_benchmark_data()

    plot_component_breakdown(components, comp_means, comp_stdevs)
    plot_env_scaling(scaling_sizes, scaling_means, scaling_stdevs)
    plot_trials_distribution(trials_data)
    print("\n[✓] All performance graphs successfully generated in docs/graphs/")

if __name__ == "__main__":
    main()
