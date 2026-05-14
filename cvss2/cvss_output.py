"""CVSS v2.10 score output formatting."""

from dataclasses import dataclass

from .cvss_base import CVSS
from .cvss_types import CvssArgs, ScoreEntry
from cvss.metric import Metric


@dataclass(frozen=True)
class ScoreDisplayData:
    """All data needed to render one score table via display_score."""

    header: tuple[str, str, str]
    footer_labels: list[str]
    metrics: list[Metric]
    footer_data: list[tuple[str, float]]
    vector_label: tuple[str, str]


def display_score(data: ScoreDisplayData) -> None:
    """Formatted score that recreates format of the CVSS examples."""

    def display_header() -> None:
        print(s1)
        h = data.header
        print(f"{h[0]:<{w0}}{h[1]:<{w0}}{h[2]}")

    def display_metrics() -> None:
        print(s1)
        for m in data.metrics:
            print(
                f"{m.name:<{w0}}{m.selected.metric:<{w0}}"
                + f"{m.selected.number:>{w1}.2f}"
            )

    def display_footer() -> None:
        print(s1)
        w2 = len(s1) - len(data.footer_labels[1])
        print(f"{data.footer_labels[0]:<{w2}}{data.footer_labels[1]}")

    def display_footer_data() -> None:
        print(s1)
        for label, value in data.footer_data:
            print(f"{label + ' =':<{2 * w0}}{value:>{w1}.2f}")
        vl = data.vector_label
        print(f"{vl[0]} Vulnerability Vector: {vl[1]}")
        print(s1)

    w0 = 30
    w1 = len(data.header[2])
    s1 = (w0 * 2 + w1) * "="
    display_header()
    display_metrics()
    display_footer()
    display_footer_data()


def _show_flags(clarg: CvssArgs) -> tuple[bool, bool, bool]:
    return (
        clarg["base"] or clarg["all"],
        clarg["temporal"] or clarg["all"],
        clarg["environmental"] or clarg["all"],
    )


def _generate_output(cvs: CVSS, clarg: CvssArgs) -> None:
    """Print requested scores."""
    show_base, show_temporal, show_env = _show_flags(clarg)
    entries: list[tuple[bool, ScoreEntry]] = [
        (show_base,
         ScoreEntry("Base", cvs.base_score, cvs.base_vulnerability_vector)),
        (show_temporal,
         ScoreEntry("Temporal", cvs.temporal_score,
                    cvs.temporal_vulnerability_vector)),
        (show_env,
         ScoreEntry("Environmental", cvs.environmental_score,
                    cvs.environmental_vulnerability_vector)),
    ]
    print()
    for show, score in entries:
        if show:
            print(f"{score.name} Score = {score.value}")
            print(f"{score.name} Vulnerability Vector = {score.vector}")
    print()


def _generate_verbose_output(cvs: CVSS, clarg: CvssArgs) -> None:
    """Generate output when verbose output requested."""
    show_base, show_temporal, show_env = _show_flags(clarg)
    entries: list[tuple[bool, ScoreDisplayData]] = [
        (show_base,
         ScoreDisplayData(
             header=("BASE METRIC", "EVALUATION", "SCORE"),
             footer_labels=["FORMULA", "BASE SCORE"],
             metrics=cvs.base_metrics(),
             footer_data=[
                 ("Impact", cvs.impact),
                 ("Exploitability", cvs.exploitability),
                 ("Base Score", cvs.base_score),
             ],
             vector_label=("Base", cvs.base_vulnerability_vector),
         )),
        (show_temporal,
         ScoreDisplayData(
             header=("TEMPORAL METRIC", "EVALUATION", "SCORE"),
             footer_labels=["FORMULA", "TEMPORAL SCORE"],
             metrics=cvs.temporal_metrics(),
             footer_data=[("Temporal Score", cvs.temporal_score)],
             vector_label=("Temporal", cvs.temporal_vulnerability_vector),
         )),
        (show_env,
         ScoreDisplayData(
             header=("ENIRONMENTAL METRIC", "EVALUATION", "SCORE"),
             footer_labels=["FORMULA", "ENIRONMENTAL SCORE"],
             metrics=cvs.environmental_metrics(),
             footer_data=[
                 ("Adjusted Impact", cvs.adjusted_impact),
                 ("Adjusted Base", cvs.adjusted_base_score),
                 ("Adjusted Temporal", cvs.adjusted_temporal_score),
                 ("Environmental Score", cvs.environmental_score),
             ],
             vector_label=(
                 "Environmental",
                 cvs.environmental_vulnerability_vector,
             ),
         )),
    ]
    for show, data in entries:
        if show:
            display_score(data)


def render_output(cvs: CVSS, clarg: CvssArgs) -> None:
    """Print scores in verbose or standard format."""
    if clarg["verbose"]:
        _generate_verbose_output(cvs, clarg)
    else:
        _generate_output(cvs, clarg)
