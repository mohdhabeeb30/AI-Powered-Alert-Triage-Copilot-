"""
Precision / Recall / F1 / Deflection Rate Evaluation Engine.

Takes a set of triage decisions and ground-truth labels, computes
the full confusion matrix and derived metrics, and renders rich
console reports with before/after comparison.
"""

from __future__ import annotations

from .schemas import Classification, EvaluationMetrics, TriageDecision


# ──────────────────────────────────────────────────────────────────────
#  Core Evaluation
# ──────────────────────────────────────────────────────────────────────

def evaluate(
    decisions: list[TriageDecision],
    ground_truth: dict[str, Classification],
) -> EvaluationMetrics:
    """
    Evaluate triage decisions against ground truth labels.

    Treats Classification.TRUE_POSITIVE as the POSITIVE class.

    Confusion Matrix:
    ┌──────────────────┬─────────────────┬─────────────────┐
    │                  │ Predicted TP    │ Predicted FP    │
    ├──────────────────┼─────────────────┼─────────────────┤
    │ Actual TP        │ True Positive   │ False Negative  │
    │ Actual FP        │ False Positive  │ True Negative   │
    └──────────────────┴─────────────────┴─────────────────┘

    Args:
        decisions: List of triage decisions from the agent.
        ground_truth: Dict mapping alert_id → actual Classification.

    Returns:
        EvaluationMetrics with all computed values.
    """
    tp = 0  # Predicted TP, Actual TP
    fp = 0  # Predicted TP, Actual FP
    tn = 0  # Predicted FP, Actual FP
    fn = 0  # Predicted FP, Actual TP

    for decision in decisions:
        actual = ground_truth.get(decision.alert_id)
        if actual is None:
            continue  # Skip alerts without ground truth

        predicted = decision.classification

        if predicted == Classification.TRUE_POSITIVE:
            if actual == Classification.TRUE_POSITIVE:
                tp += 1
            else:
                fp += 1
        else:  # predicted == FP
            if actual == Classification.FALSE_POSITIVE:
                tn += 1
            else:
                fn += 1

    total = tp + fp + tn + fn

    # Calculate metrics with zero-division protection
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * (precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    # Deflection Rate: % of actual FP alerts correctly identified as FP
    deflection = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    return EvaluationMetrics(
        total_alerts=total,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        deflection_rate=round(deflection, 4),
    )


# ──────────────────────────────────────────────────────────────────────
#  Rich Console Reports
# ──────────────────────────────────────────────────────────────────────

def print_metrics_report(
    metrics: EvaluationMetrics,
    label: str = "Evaluation",
) -> None:
    """
    Print a rich, formatted metrics report to the console.

    Uses the `rich` library for beautiful table output.
    Falls back to plain text if rich is not installed.
    """
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console()

        # ── Confusion Matrix Table ──
        cm_table = Table(
            title="Confusion Matrix",
            show_header=True,
            header_style="bold cyan",
        )
        cm_table.add_column("", style="bold")
        cm_table.add_column("Predicted TP", justify="center", style="red")
        cm_table.add_column("Predicted FP", justify="center", style="green")
        cm_table.add_row(
            "Actual TP",
            f"[bold green]{metrics.true_positives}[/] (TP)",
            f"[bold red]{metrics.false_negatives}[/] (FN)",
        )
        cm_table.add_row(
            "Actual FP",
            f"[bold red]{metrics.false_positives}[/] (FP)",
            f"[bold green]{metrics.true_negatives}[/] (TN)",
        )

        # ── Metrics Table ──
        m_table = Table(
            title="Performance Metrics",
            show_header=True,
            header_style="bold magenta",
        )
        m_table.add_column("Metric", style="bold")
        m_table.add_column("Value", justify="right")
        m_table.add_column("Interpretation", style="dim")

        precision_pct = f"{metrics.precision * 100:.1f}%"
        recall_pct = f"{metrics.recall * 100:.1f}%"
        f1_pct = f"{metrics.f1_score * 100:.1f}%"
        deflection_pct = f"{metrics.deflection_rate * 100:.1f}%"

        m_table.add_row(
            "Precision",
            precision_pct,
            "Of alerts flagged as threats, % that are real",
        )
        m_table.add_row(
            "Recall (TPR)",
            recall_pct,
            "Of real threats, % correctly detected",
        )
        m_table.add_row(
            "F1-Score",
            f1_pct,
            "Harmonic mean of Precision & Recall",
        )
        m_table.add_row(
            "Deflection Rate",
            deflection_pct,
            "% of false alarms correctly suppressed",
        )
        m_table.add_row(
            "Total Alerts",
            str(metrics.total_alerts),
            "",
        )

        console.print()
        console.print(Panel(
            f"[bold]{label}[/bold]",
            style="bold blue",
            expand=False,
        ))
        console.print(cm_table)
        console.print(m_table)
        console.print()

    except ImportError:
        _print_plain(metrics, label)


def _print_plain(metrics: EvaluationMetrics, label: str) -> None:
    """Fallback plain-text metrics report."""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(f"  Confusion Matrix:")
    print(f"    TP: {metrics.true_positives}  |  FN: {metrics.false_negatives}")
    print(f"    FP: {metrics.false_positives}  |  TN: {metrics.true_negatives}")
    print(f"  ────────────────────────────────")
    print(f"  Precision      : {metrics.precision * 100:.1f}%")
    print(f"  Recall (TPR)   : {metrics.recall * 100:.1f}%")
    print(f"  F1-Score       : {metrics.f1_score * 100:.1f}%")
    print(f"  Deflection Rate: {metrics.deflection_rate * 100:.1f}%")
    print(f"  Total Alerts   : {metrics.total_alerts}")
    print(f"{'='*60}\n")


def compare_metrics(
    before: EvaluationMetrics,
    after: EvaluationMetrics,
) -> None:
    """
    Print a side-by-side comparison of metrics before and after
    analyst feedback, highlighting improvements.
    """
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console()

        table = Table(
            title="📊 Metrics Improvement After Analyst Feedback",
            show_header=True,
            header_style="bold yellow",
        )
        table.add_column("Metric", style="bold")
        table.add_column("Before", justify="right", style="red")
        table.add_column("After", justify="right", style="green")
        table.add_column("Delta", justify="right")

        for name, b_val, a_val in [
            ("Precision", before.precision, after.precision),
            ("Recall (TPR)", before.recall, after.recall),
            ("F1-Score", before.f1_score, after.f1_score),
            ("Deflection Rate", before.deflection_rate, after.deflection_rate),
        ]:
            delta = a_val - b_val
            delta_str = f"{delta * 100:+.1f}%"
            if delta > 0:
                delta_str = f"[bold green]▲ {delta_str}[/]"
            elif delta < 0:
                delta_str = f"[bold red]▼ {delta_str}[/]"
            else:
                delta_str = f"[dim]— {delta_str}[/]"

            table.add_row(
                name,
                f"{b_val * 100:.1f}%",
                f"{a_val * 100:.1f}%",
                delta_str,
            )

        # Confusion matrix changes
        table.add_section()
        for name, b_val, a_val in [
            ("True Positives", before.true_positives, after.true_positives),
            ("False Positives", before.false_positives, after.false_positives),
            ("True Negatives", before.true_negatives, after.true_negatives),
            ("False Negatives", before.false_negatives, after.false_negatives),
        ]:
            delta = a_val - b_val
            if delta > 0:
                delta_str = f"[green]+{delta}[/]"
            elif delta < 0:
                delta_str = f"[red]{delta}[/]"
            else:
                delta_str = "[dim]0[/]"

            table.add_row(name, str(b_val), str(a_val), delta_str)

        console.print()
        console.print(Panel(
            "[bold green]✅ Feedback Loop Impact Analysis[/bold green]",
            style="green",
            expand=False,
        ))
        console.print(table)
        console.print()

    except ImportError:
        print("\n── Before vs After Feedback ──")
        for name, b_val, a_val in [
            ("Precision", before.precision, after.precision),
            ("Recall", before.recall, after.recall),
            ("F1-Score", before.f1_score, after.f1_score),
            ("Deflection", before.deflection_rate, after.deflection_rate),
        ]:
            delta = (a_val - b_val) * 100
            print(f"  {name:20s}: {b_val*100:.1f}% → {a_val*100:.1f}% ({delta:+.1f}%)")
        print()
