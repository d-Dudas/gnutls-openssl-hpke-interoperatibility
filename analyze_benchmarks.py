#!/usr/bin/env python3

import argparse
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


def confidence_interval_95(mean, std, n):
    if n <= 1 or pd.isna(std):
        return mean, mean

    margin = 1.96 * (std / (n ** 0.5))
    return mean - margin, mean + margin


def confidence_intervals_overlap(low1, high1, low2, high2):
    return low1 <= high2 and low2 <= high1


def safe_filename(name):
    if pd.isna(name) or name == "":
        return "whole_procedure"

    return (
        str(name)
        .replace("/", "_")
        .replace("\\", "_")
        .replace(" ", "_")
        .replace(":", "_")
    )


def build_label(procedure, subprocedure):
    if subprocedure == "":
        return f"{procedure} / whole"
    return f"{procedure} / {subprocedure}"


def compute_statistics(df):
    rows = []

    grouped = df.groupby(["procedure", "subprocedure", "library"], dropna=False)

    for (procedure, subprocedure, library), group in grouped:
        durations = group["duration"]

        count = durations.count()
        average = durations.mean()
        median = durations.median()
        std_deviation = durations.std(ddof=1)
        minimum = durations.min()
        maximum = durations.max()
        p90 = durations.quantile(0.90)
        p95 = durations.quantile(0.95)
        p99 = durations.quantile(0.99)
        variance = durations.var(ddof=1)

        coefficient_of_variation = (
            std_deviation / average if average != 0 else float("nan")
        )

        ci_low, ci_high = confidence_interval_95(
            average,
            std_deviation,
            count,
        )

        rows.append(
            {
                "library": library,
                "procedure": procedure,
                "subprocedure": subprocedure,
                "scope": "whole_procedure" if subprocedure == "" else "subprocedure",
                "operation_label": build_label(procedure, subprocedure),
                "count": count,
                "average": average,
                "median": median,
                "std_deviation": std_deviation,
                "min": minimum,
                "max": maximum,
                "p90": p90,
                "p95": p95,
                "p99": p99,
                "variance": variance,
                "coefficient_of_variation": coefficient_of_variation,
                "confidence_interval_95_low": ci_low,
                "confidence_interval_95_high": ci_high,
            }
        )

    return pd.DataFrame(rows)


def add_comparisons(stats_df):
    comparison_rows = []

    grouped = stats_df.groupby(["procedure", "subprocedure"], dropna=False)

    for (procedure, subprocedure), operation_stats in grouped:
        fastest_row = operation_stats.loc[operation_stats["average"].idxmin()]

        fastest_library = fastest_row["library"]
        fastest_average = fastest_row["average"]
        fastest_ci_low = fastest_row["confidence_interval_95_low"]
        fastest_ci_high = fastest_row["confidence_interval_95_high"]
        operation_label = fastest_row["operation_label"]

        for _, row in operation_stats.iterrows():
            average = row["average"]
            median = row["median"]

            absolute_difference_vs_fastest = average - fastest_average

            if fastest_average != 0:
                speed_ratio_vs_fastest = average / fastest_average
                percentage_slower_vs_fastest = (
                    absolute_difference_vs_fastest / fastest_average
                ) * 100
            else:
                speed_ratio_vs_fastest = float("nan")
                percentage_slower_vs_fastest = float("nan")

            if fastest_row["median"] != 0:
                median_ratio_vs_fastest = median / fastest_row["median"]
            else:
                median_ratio_vs_fastest = float("nan")

            ci_overlap = confidence_intervals_overlap(
                row["confidence_interval_95_low"],
                row["confidence_interval_95_high"],
                fastest_ci_low,
                fastest_ci_high,
            )

            if row["library"] == fastest_library:
                interpretation = (
                    f"Fastest library for {operation_label}; baseline for comparison."
                )
            else:
                significance = (
                    "confidence intervals do not overlap"
                    if not ci_overlap
                    else "confidence intervals overlap"
                )

                interpretation = (
                    f"{row['library']} is approximately "
                    f"{speed_ratio_vs_fastest:.2f}x slower than "
                    f"{fastest_library} for {operation_label} "
                    f"({percentage_slower_vs_fastest:.2f}% slower); "
                    f"{significance}."
                )

            comparison_rows.append(
                {
                    **row.to_dict(),
                    "fastest_library_for_operation": fastest_library,
                    "absolute_difference_vs_fastest": absolute_difference_vs_fastest,
                    "percentage_slower_vs_fastest": percentage_slower_vs_fastest,
                    "speed_ratio_vs_fastest": speed_ratio_vs_fastest,
                    "median_ratio_vs_fastest": median_ratio_vs_fastest,
                    "confidence_interval_overlaps_fastest": ci_overlap,
                    "interpretation": interpretation,
                }
            )

    return pd.DataFrame(comparison_rows)


def generate_boxplots(df, graphs_dir):
    for (procedure, subprocedure), operation_df in df.groupby(
        ["procedure", "subprocedure"],
        dropna=False,
    ):
        plt.figure(figsize=(10, 6))

        libraries = operation_df["library"].unique()
        data = [
            operation_df[operation_df["library"] == library]["duration"]
            for library in libraries
        ]

        title_label = build_label(procedure, subprocedure)

        plt.boxplot(data, labels=libraries, showmeans=True)
        plt.title(f"Duration distribution: {title_label}")
        plt.xlabel("Library")
        plt.ylabel("Duration")
        plt.grid(axis="y", alpha=0.3)

        graph_path = graphs_dir / (
            f"boxplot_{safe_filename(procedure)}_{safe_filename(subprocedure)}.png"
        )

        plt.tight_layout()
        plt.savefig(graph_path, dpi=150)
        plt.close()

        print(f"Boxplot saved to: {graph_path}")

def generate_stacked_area_graphs(stats_df, graphs_dir):
    for procedure, procedure_df in stats_df.groupby("procedure"):
        whole_df = procedure_df[procedure_df["scope"] == "whole_procedure"]
        sub_df = procedure_df[procedure_df["scope"] == "subprocedure"]

        if whole_df.empty or sub_df.empty:
            continue

        whole_pivot = whole_df.pivot_table(
            index="library",
            values="average",
            aggfunc="mean",
        )

        sub_pivot = sub_df.pivot_table(
            index="library",
            columns="subprocedure",
            values="average",
            aggfunc="mean",
            fill_value=0,
        )

        common_libraries = whole_pivot.index.intersection(sub_pivot.index)

        if common_libraries.empty:
            continue

        whole_pivot = whole_pivot.loc[common_libraries]
        sub_pivot = sub_pivot.loc[common_libraries]

        sub_sum = sub_pivot.sum(axis=1)
        whole_duration = whole_pivot["average"]

        remaining_duration = whole_duration - sub_sum
        remaining_duration = remaining_duration.clip(lower=0)

        sub_pivot["unmeasured_or_overhead"] = remaining_duration

        sub_pivot = sub_pivot.sort_index()
        whole_duration = whole_duration.loc[sub_pivot.index]

        x = range(len(sub_pivot.index))
        y_values = [sub_pivot[col].values for col in sub_pivot.columns]

        plt.figure(figsize=(12, 6))

        plt.stackplot(
            x,
            y_values,
            labels=sub_pivot.columns,
        )

        plt.plot(
            x,
            whole_duration.values,
            marker="o",
            linewidth=2,
            label="whole procedure",
        )

        plt.xticks(x, sub_pivot.index)
        plt.title(f"Subprocedure contribution to whole procedure: {procedure}")
        plt.xlabel("Library")
        plt.ylabel("Average duration")
        plt.legend(loc="upper left")
        plt.grid(axis="y", alpha=0.3)

        graph_path = graphs_dir / f"stacked_area_{safe_filename(procedure)}.png"

        plt.tight_layout()
        plt.savefig(graph_path, dpi=150)
        plt.close()

        print(f"Stacked area graph saved to: {graph_path}")

def main():
    parser = argparse.ArgumentParser(
        description="Analyze benchmark CSV data and generate graphs/statistics."
    )
    parser.add_argument(
        "csv_file",
        help="Path to CSV file with columns: library,procedure,subprocedure,duration",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="benchmark_results",
        help="Directory where graphs and statistics will be saved",
    )
    parser.add_argument(
        "--has-header",
        action="store_true",
        help="Use this if the CSV file already has a header row",
    )

    args = parser.parse_args()

    csv_path = Path(args.csv_file)
    output_dir = Path(args.output_dir)
    graphs_dir = output_dir / "graphs"

    output_dir.mkdir(exist_ok=True)
    graphs_dir.mkdir(exist_ok=True)

    if args.has_header:
        df = pd.read_csv(csv_path)
    else:
        df = pd.read_csv(
            csv_path,
            names=["library", "procedure", "subprocedure", "duration"],
            header=None,
        )

    required_columns = {"library", "procedure", "subprocedure", "duration"}
    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(f"Missing required columns: {missing_columns}")

    df["subprocedure"] = df["subprocedure"].fillna("")
    df["duration"] = pd.to_numeric(df["duration"], errors="coerce")
    df = df.dropna(subset=["duration"])

    stats_df = compute_statistics(df)
    final_stats_df = add_comparisons(stats_df)
    final_stats_df = final_stats_df.sort_values(
        ["procedure", "scope", "subprocedure", "average"]
    )

    stats_output = output_dir / "statistics.csv"
    final_stats_df.to_csv(stats_output, index=False)

    print(f"Statistics saved to: {stats_output}")

    whole_procedure_stats = final_stats_df[
        final_stats_df["scope"] == "whole_procedure"
    ]
    subprocedure_stats = final_stats_df[
        final_stats_df["scope"] == "subprocedure"
    ]

    whole_procedure_stats.to_csv(
        output_dir / "whole_procedure_statistics.csv",
        index=False,
    )

    subprocedure_stats.to_csv(
        output_dir / "subprocedure_statistics.csv",
        index=False,
    )

    print(f"Whole procedure statistics saved to: {output_dir / 'whole_procedure_statistics.csv'}")
    print(f"Subprocedure statistics saved to: {output_dir / 'subprocedure_statistics.csv'}")

    generate_boxplots(df, graphs_dir)
    generate_stacked_area_graphs(final_stats_df, graphs_dir)


if __name__ == "__main__":
    main()
