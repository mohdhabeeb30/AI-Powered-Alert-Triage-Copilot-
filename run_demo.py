#!/usr/bin/env python3
"""
AI-Powered Alert Triage Copilot — End-to-End Lifecycle Demo.

Demonstrates the complete pipeline:
  1. INGEST   → Load 5 mock security alerts
  2. TRIAGE   → Classify alerts (Pass 1 — intentional misclassification)
  3. EVALUATE → Compute Precision/Recall/F1/Deflection (Before)
  4. FEEDBACK → Analyst corrects Alert #3 (Port Scan: TP → FP)
  5. RE-TRIAGE → Classify again with feedback-enhanced prompts (Pass 2)
  6. EVALUATE → Compute improved metrics (After)
  7. COMPARE  → Side-by-side delta analysis

Usage:
    python run_demo.py           # Mock mode (no API key needed)
    python run_demo.py --live    # Live Gemini mode (requires GOOGLE_API_KEY)
"""

from __future__ import annotations

import asyncio
import sys

# ──────────────────────────────────────────────────────────────────────
#  Rich Console Setup
# ──────────────────────────────────────────────────────────────────────

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box

    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

    class _FallbackConsole:
        def print(self, *args, **kwargs):
            # Strip rich markup for plain output
            text = " ".join(str(a) for a in args)
            print(text)
        def rule(self, title="", **kwargs):
            print(f"\n{'─'*60}")
            if title:
                print(f"  {title}")
            print(f"{'─'*60}")

    console = _FallbackConsole()


def _header(text: str) -> None:
    """Print a styled section header."""
    if HAS_RICH:
        console.print()
        console.rule(f"[bold cyan]{text}[/bold cyan]", style="cyan")
        console.print()
    else:
        console.rule(text)


def _print_decision(decision, index: int) -> None:
    """Print a single triage decision."""
    from alert_triage_copilot.schemas import Classification

    if HAS_RICH:
        cls_color = "red" if decision.classification == Classification.TRUE_POSITIVE else "green"
        cls_icon = "🚨" if decision.classification == Classification.TRUE_POSITIVE else "✅"

        panel_content = (
            f"  Classification : [{cls_color} bold]{cls_icon} {decision.classification.value}[/]\n"
            f"  Confidence     : {decision.confidence:.0%}\n"
            f"  Reasoning      : {decision.reasoning[:200]}...\n"
            f"  Action         : {decision.recommended_action[:120]}...\n"
        )
        if decision.mitre_tactics:
            panel_content += f"  MITRE Tactics  : {', '.join(decision.mitre_tactics)}\n"
        if decision.analyst_notes:
            panel_content += f"  Analyst Notes  : [italic]{decision.analyst_notes}[/italic]\n"

        console.print(Panel(
            panel_content,
            title=f"[bold]Alert {index}: {decision.alert_id}[/bold]",
            border_style=cls_color,
            expand=False,
        ))
    else:
        cls_icon = "🚨" if decision.classification == Classification.TRUE_POSITIVE else "✅"
        print(f"\n  Alert {index}: {decision.alert_id}")
        print(f"    Classification : {cls_icon} {decision.classification.value}")
        print(f"    Confidence     : {decision.confidence:.0%}")
        print(f"    Reasoning      : {decision.reasoning[:150]}...")
        print(f"    Action         : {decision.recommended_action[:100]}...")


# ──────────────────────────────────────────────────────────────────────
#  Main Demo
# ──────────────────────────────────────────────────────────────────────

async def run_demo(live_mode: bool = False) -> None:
    """Execute the full triage lifecycle demo."""

    from alert_triage_copilot.db import SessionLocal, init_db
    from alert_triage_copilot.evaluation import (
        compare_metrics,
        evaluate,
        print_metrics_report,
    )
    from alert_triage_copilot.feedback_loop import FeedbackStore
    from alert_triage_copilot.mock_data import get_ground_truth, get_mock_alerts
    from alert_triage_copilot.schemas import Classification
    from alert_triage_copilot.triage_engine import triage_batch, triage_with_feedback

    # ═══════════════════════════════════════════════════════════════════
    #  Banner
    # ═══════════════════════════════════════════════════════════════════

    if HAS_RICH:
        banner = Text()
        banner.append("🛡️  AI-Powered Alert Triage Copilot\n", style="bold cyan")
        banner.append("    Built with Google ADK 2.0\n", style="dim")
        mode_text = "🌐 LIVE (Gemini)" if live_mode else "🔧 MOCK (Deterministic)"
        banner.append(f"    Mode: {mode_text}\n", style="bold yellow")
        console.print(Panel(banner, border_style="bright_blue", expand=False))
    else:
        print("\n╔══════════════════════════════════════════╗")
        print("║  🛡️  AI-Powered Alert Triage Copilot     ║")
        print("║     Built with Google ADK 2.0            ║")
        mode_text = "LIVE (Gemini)" if live_mode else "MOCK (Deterministic)"
        print(f"║     Mode: {mode_text:30s}  ║")
        print("╚══════════════════════════════════════════╝")

    # ═══════════════════════════════════════════════════════════════════
    #  DATABASE INIT
    # ═══════════════════════════════════════════════════════════════════

    init_db()
    db_session = SessionLocal()

    # ═══════════════════════════════════════════════════════════════════
    #  PHASE 1: INGESTION
    # ═══════════════════════════════════════════════════════════════════

    _header("PHASE 1: ALERT INGESTION")

    alerts = get_mock_alerts()
    ground_truth = get_ground_truth()

    if HAS_RICH:
        table = Table(
            title="Ingested Security Alerts",
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED,
        )
        table.add_column("#", justify="center", width=3)
        table.add_column("Alert ID", style="cyan")
        table.add_column("Type", style="bold")
        table.add_column("Severity", justify="center")
        table.add_column("Source", style="dim")
        table.add_column("Ground Truth", justify="center")

        severity_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
            "informational": "dim",
        }

        for i, alert in enumerate(alerts, 1):
            gt = ground_truth[alert.alert_id]
            gt_style = "red" if gt == Classification.TRUE_POSITIVE else "green"
            sev_style = severity_colors.get(alert.severity.value, "white")

            table.add_row(
                str(i),
                alert.alert_id,
                alert.alert_type,
                f"[{sev_style}]{alert.severity.value.upper()}[/]",
                alert.source,
                f"[{gt_style}]{gt.value}[/]",
            )

        console.print(table)
    else:
        print("\n  Ingested Alerts:")
        for i, alert in enumerate(alerts, 1):
            gt = ground_truth[alert.alert_id]
            print(f"    {i}. {alert.alert_id} | {alert.alert_type:25s} | "
                  f"{alert.severity.value.upper():10s} | GT: {gt.value}")

    console.print(f"\n  📥 Loaded {len(alerts)} alerts with ground truth labels.\n")

    # ═══════════════════════════════════════════════════════════════════
    #  PHASE 2: TRIAGE — PASS 1 (No Feedback)
    # ═══════════════════════════════════════════════════════════════════

    _header("PHASE 2: TRIAGE — PASS 1 (No Feedback)")

    console.print("  ⚡ Running triage on all alerts...\n")

    decisions_pass1 = await triage_batch(
        alerts,
        feedback_store=None,
        live_mode=live_mode,
    )

    for i, decision in enumerate(decisions_pass1, 1):
        _print_decision(decision, i)

    # Highlight the misclassification
    scan_decision = next(
        (d for d in decisions_pass1 if d.alert_id == "ALERT-SCAN03"),
        None,
    )
    if scan_decision and scan_decision.classification == Classification.TRUE_POSITIVE:
        if HAS_RICH:
            console.print(Panel(
                "[bold yellow]⚠️  Alert ALERT-SCAN03 (Port Scan) was classified as TP,\n"
                "   but it's actually a scheduled Nessus scan (FP)!\n"
                "   → This is why we need the human-in-the-loop feedback.[/bold yellow]",
                border_style="yellow",
                title="[bold]Misclassification Detected[/bold]",
                expand=False,
            ))
        else:
            print("\n  ⚠️  ALERT-SCAN03 misclassified as TP — it's a scheduled scan (FP)!")

    # ═══════════════════════════════════════════════════════════════════
    #  PHASE 3: EVALUATION — BEFORE FEEDBACK
    # ═══════════════════════════════════════════════════════════════════

    _header("PHASE 3: EVALUATION — BEFORE FEEDBACK")

    metrics_before = evaluate(decisions_pass1, ground_truth)
    print_metrics_report(metrics_before, "Pass 1 — Before Analyst Feedback")

    # ═══════════════════════════════════════════════════════════════════
    #  PHASE 4: HUMAN-IN-THE-LOOP FEEDBACK
    # ═══════════════════════════════════════════════════════════════════

    _header("PHASE 4: HUMAN-IN-THE-LOOP — ANALYST FEEDBACK")

    feedback_store = FeedbackStore(db_session)

    # Analyst corrects Alert #3
    scan_alert = next(a for a in alerts if a.alert_id == "ALERT-SCAN03")

    fb = feedback_store.submit_feedback(
        alert=scan_alert,
        original_classification=Classification.TRUE_POSITIVE,
        corrected_classification=Classification.FALSE_POSITIVE,
        analyst_id="soc-analyst-42",
        feedback_notes=(
            "This is IP 10.0.50.10, our registered Nessus vulnerability scanner. "
            "The scan was pre-approved under change ticket CHG-2026-04521 with a "
            "scheduled window of 14:00-16:00 UTC. The scanner fingerprint matches "
            "Nessus/10.7.0. This is a routine scheduled scan, NOT a threat. "
            "Recommend adding 10.0.50.10 to the scanner allowlist to prevent "
            "future false positives."
        ),
    )

    if HAS_RICH:
        fb_panel = (
            f"  Alert ID     : [cyan]{fb.alert_id}[/cyan]\n"
            f"  Analyst      : [bold]{fb.analyst_id}[/bold]\n"
            f"  Original     : [red]{fb.original_classification.value}[/red]\n"
            f"  Corrected    : [green]{fb.corrected_classification.value}[/green]\n"
            f"  Notes        : [italic]{fb.feedback_notes[:200]}[/italic]\n"
        )
        console.print(Panel(
            fb_panel,
            title="[bold green]✏️  Analyst Correction Submitted[/bold green]",
            border_style="green",
            expand=False,
        ))
    else:
        print(f"\n  ✏️  Analyst Correction:")
        print(f"    Alert: {fb.alert_id}")
        print(f"    {fb.original_classification.value} → {fb.corrected_classification.value}")
        print(f"    Analyst: {fb.analyst_id}")
        print(f"    Notes: {fb.feedback_notes[:150]}...")

    # Show feedback store stats
    stats = feedback_store.get_correction_stats()
    console.print(f"\n  📋 Feedback Store: {stats['total_corrections']} correction(s)")
    console.print(f"     TP→FP: {stats['tp_to_fp_corrections']}, FP→TP: {stats['fp_to_tp_corrections']}")
    console.print(f"     By type: {stats['corrections_by_alert_type']}\n")

    # ═══════════════════════════════════════════════════════════════════
    #  PHASE 5: RE-TRIAGE — PASS 2 (With Feedback)
    # ═══════════════════════════════════════════════════════════════════

    _header("PHASE 5: RE-TRIAGE — PASS 2 (With Feedback)")

    console.print("  🔄 Re-running triage with feedback-enhanced prompts...\n")

    decisions_pass2 = await triage_with_feedback(
        alerts,
        feedback_store=feedback_store,
        live_mode=live_mode,
    )

    for i, decision in enumerate(decisions_pass2, 1):
        _print_decision(decision, i)

    # Highlight the correction
    scan_decision_2 = next(
        (d for d in decisions_pass2 if d.alert_id == "ALERT-SCAN03"),
        None,
    )
    if scan_decision_2 and scan_decision_2.classification == Classification.FALSE_POSITIVE:
        if HAS_RICH:
            console.print(Panel(
                "[bold green]✅ Alert ALERT-SCAN03 now correctly classified as FP!\n"
                "   The feedback loop successfully corrected the misclassification.[/bold green]",
                border_style="green",
                title="[bold]Correction Applied[/bold]",
                expand=False,
            ))
        else:
            print("\n  ✅ ALERT-SCAN03 now correctly classified as FP after feedback!")

    # ═══════════════════════════════════════════════════════════════════
    #  PHASE 6: EVALUATION — AFTER FEEDBACK
    # ═══════════════════════════════════════════════════════════════════

    _header("PHASE 6: EVALUATION — AFTER FEEDBACK")

    metrics_after = evaluate(decisions_pass2, ground_truth)
    print_metrics_report(metrics_after, "Pass 2 — After Analyst Feedback")

    # ═══════════════════════════════════════════════════════════════════
    #  PHASE 7: METRICS COMPARISON
    # ═══════════════════════════════════════════════════════════════════

    _header("PHASE 7: BEFORE vs AFTER — IMPACT ANALYSIS")

    compare_metrics(metrics_before, metrics_after)

    # ═══════════════════════════════════════════════════════════════════
    #  Summary
    # ═══════════════════════════════════════════════════════════════════

    _header("LIFECYCLE COMPLETE")

    if HAS_RICH:
        summary = (
            "[bold green]The AI-Powered Alert Triage Copilot successfully demonstrated:[/bold green]\n\n"
            "  1. [cyan]📥 Ingestion[/cyan]    — Loaded 5 diverse security alerts\n"
            "  2. [cyan]🤖 Triage[/cyan]       — LLM classified alerts with reasoning & MITRE mapping\n"
            "  3. [cyan]📊 Evaluation[/cyan]   — Measured Precision, Recall, F1, Deflection Rate\n"
            "  4. [cyan]✏️  Feedback[/cyan]     — Analyst corrected a misclassification\n"
            "  5. [cyan]🔄 Re-Triage[/cyan]    — Feedback-enhanced pass corrected the error\n"
            "  6. [cyan]📈 Improvement[/cyan]  — Metrics improved across all dimensions\n\n"
            f"  [bold]Precision:  {metrics_before.precision*100:.0f}% → {metrics_after.precision*100:.0f}%[/bold]\n"
            f"  [bold]F1-Score:   {metrics_before.f1_score*100:.0f}% → {metrics_after.f1_score*100:.0f}%[/bold]\n"
            f"  [bold]Deflection: {metrics_before.deflection_rate*100:.0f}% → {metrics_after.deflection_rate*100:.0f}%[/bold]"
        )
        console.print(Panel(
            summary,
            title="[bold]🛡️  Mission Accomplished[/bold]",
            border_style="bright_green",
            expand=False,
        ))
    else:
        print("\n  ✅ Lifecycle complete!")
        print(f"     Precision:  {metrics_before.precision*100:.0f}% → {metrics_after.precision*100:.0f}%")
        print(f"     F1-Score:   {metrics_before.f1_score*100:.0f}% → {metrics_after.f1_score*100:.0f}%")
        print(f"     Deflection: {metrics_before.deflection_rate*100:.0f}% → {metrics_after.deflection_rate*100:.0f}%")

    db_session.close()


# ──────────────────────────────────────────────────────────────────────
#  Entry Point
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    live_mode = "--live" in sys.argv

    if live_mode:
        import os
        if not os.getenv("GOOGLE_API_KEY"):
            print("❌ Error: GOOGLE_API_KEY environment variable not set.")
            print("   Set it with: export GOOGLE_API_KEY='your-key-here'")
            print("   Or run without --live flag for mock mode.")
            sys.exit(1)

    asyncio.run(run_demo(live_mode=live_mode))
