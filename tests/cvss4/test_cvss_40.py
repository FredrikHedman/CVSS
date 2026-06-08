"""Tests for CVSS v4.0 vector parsing and scoring.

Test vectors sourced from https://www.first.org/cvss/v4.0/examples
"""

import pytest

from cvss4.cvss_40 import CommonVulnerabilityScore40
from cvss4.cvss_types import CVSS40Result
from cvss4.cvss_40 import _eq1  # pyright: ignore[reportPrivateUsage]
from cvss4.cvss_40 import _eq2  # pyright: ignore[reportPrivateUsage]
from cvss4.cvss_40 import _eq3  # pyright: ignore[reportPrivateUsage]
from cvss4.cvss_40 import _eq4  # pyright: ignore[reportPrivateUsage]
from cvss4.cvss_40 import _eq5  # pyright: ignore[reportPrivateUsage]
from cvss4.cvss_40 import _eq6  # pyright: ignore[reportPrivateUsage]
from cvss4.cvss_40 import _EQ1_MAX  # pyright: ignore[reportPrivateUsage]
from cvss4.cvss_40 import _EQ2_MAX  # pyright: ignore[reportPrivateUsage]
from cvss4.cvss_40 import _EQ3EQ6_MAX  # pyright: ignore[reportPrivateUsage]
from cvss4.cvss_40 import _EQ4_MAX  # pyright: ignore[reportPrivateUsage]
from cvss4.cvss_40 import _EQ5_MAX  # pyright: ignore[reportPrivateUsage]
from cvss.vulnerability import InvalidVectorError
from cvss4.vulnerability_40 import VulnerabilityVector40
from cvss4.vulnerability_40 import _ALL_ALLOWED  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# Vector parsing tests
# ---------------------------------------------------------------------------

_VALID_BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def test_parse_valid_base_vector() -> None:
    v = VulnerabilityVector40(_VALID_BASE)
    assert v.parsed["AV"] == "N"
    assert v.parsed["SA"] == "N"


def test_parse_rejects_missing_prefix() -> None:
    with pytest.raises(InvalidVectorError, match="CVSS:4.0/"):
        _ = VulnerabilityVector40(
            "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        )


def test_parse_rejects_bad_metric_key() -> None:
    with pytest.raises(InvalidVectorError):
        _ = VulnerabilityVector40(_VALID_BASE.replace("AV:N", "XX:N"))


def test_parse_rejects_bad_value() -> None:
    with pytest.raises(InvalidVectorError):
        _ = VulnerabilityVector40(_VALID_BASE.replace("AV:N", "AV:Z"))


def test_parse_rejects_missing_base_metric() -> None:
    incomplete = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N"
    with pytest.raises(InvalidVectorError, match="Missing"):
        _ = VulnerabilityVector40(incomplete)


def test_defaults_absent_optional_to_x() -> None:
    v = VulnerabilityVector40(_VALID_BASE)
    assert v.parsed["E"] == "X"
    assert v.parsed["CR"] == "X"
    assert v.parsed["MAV"] == "X"


def test_parsed_is_cached() -> None:
    v = VulnerabilityVector40(_VALID_BASE)
    assert v.parsed is v.parsed


def test_parse_rejects_duplicate_metric() -> None:
    dup = (
        "CVSS:4.0/AV:N/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    )
    with pytest.raises(InvalidVectorError, match="Duplicate"):
        _ = VulnerabilityVector40(dup)


# ---------------------------------------------------------------------------
# EQ level function tests (Spec §7.5 boundary conditions)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "p,expected",
    [
        ({"AV": "N", "PR": "N", "UI": "N"}, 0),  # AV:N AND PR:N AND UI:N → 0
        ({"AV": "N", "PR": "L", "UI": "A"}, 1),  # at least one is N → 1
        ({"AV": "P", "PR": "H", "UI": "A"}, 2),  # none is N → 2
    ],
)
def test_eq1(p: dict[str, str], expected: int) -> None:
    assert _eq1(p) == expected


@pytest.mark.parametrize(
    "p,expected",
    [
        ({"AC": "L", "AT": "N"}, 0),
        ({"AC": "H", "AT": "N"}, 1),
        ({"AC": "L", "AT": "P"}, 1),
    ],
)
def test_eq2(p: dict[str, str], expected: int) -> None:
    assert _eq2(p) == expected


@pytest.mark.parametrize(
    "p,expected",
    [
        ({"VC": "H", "VI": "H", "VA": "N"}, 0),  # VC:H AND VI:H → 0
        ({"VC": "H", "VI": "N", "VA": "N"}, 1),  # VC:H but not both H → 1
        ({"VC": "N", "VI": "N", "VA": "L"}, 2),  # no H → 2
        # Modified metrics override the base value (Spec §7.5):
        # effective VC/VI/VA = M* when set, else base.
        ({"VC": "N", "VI": "N", "VA": "N", "MVC": "H", "MVI": "H"}, 0),
        ({"VC": "N", "VI": "N", "VA": "N", "MVC": "H"}, 1),
        ({"VC": "H", "VI": "H", "VA": "N", "MVC": "N", "MVI": "N"}, 2),
    ],
)
def test_eq3(p: dict[str, str], expected: int) -> None:
    assert _eq3(p) == expected


@pytest.mark.parametrize(
    "p,expected",
    [
        (
            {
                "SI": "S",
                "SA": "N",
                "SC": "N",
                "MSI": "X",
                "MSA": "X",
                "MSC": "X",
            },
            0,
        ),
        (
            {
                "SI": "H",
                "SA": "N",
                "SC": "N",
                "MSI": "X",
                "MSA": "X",
                "MSC": "X",
            },
            1,
        ),
        (
            {
                "SI": "N",
                "SA": "N",
                "SC": "N",
                "MSI": "X",
                "MSA": "X",
                "MSC": "X",
            },
            2,
        ),
    ],
)
def test_eq4(p: dict[str, str], expected: int) -> None:
    assert _eq4(p) == expected


@pytest.mark.parametrize(
    "p,expected",
    [
        ({"E": "X"}, 0),  # X → treated as A (Attacked) → 0
        ({"E": "A"}, 0),
        ({"E": "P"}, 1),
        ({"E": "U"}, 2),
    ],
)
def test_eq5(p: dict[str, str], expected: int) -> None:
    assert _eq5(p) == expected


@pytest.mark.parametrize(
    "p,expected",
    [
        # CR:H and VC:H → aligned → 0
        (
            {
                "CR": "H",
                "VC": "H",
                "IR": "L",
                "VI": "L",
                "AR": "L",
                "VA": "L",
                "MVC": "X",
                "MVI": "X",
                "MVA": "X",
            },
            0,
        ),
        # no alignment → 1
        (
            {
                "CR": "L",
                "VC": "H",
                "IR": "L",
                "VI": "L",
                "AR": "L",
                "VA": "L",
                "MVC": "X",
                "MVI": "X",
                "MVA": "X",
            },
            1,
        ),
    ],
)
def test_eq6(p: dict[str, str], expected: int) -> None:
    assert _eq6(p) == expected


# ---------------------------------------------------------------------------
# _EQ*_MAX validity test
# ---------------------------------------------------------------------------


def test_eq_max_vectors_valid() -> None:
    """Every metric:value pair in _EQ*_MAX strings is a valid metric value."""
    flat: list[str] = []
    for d in [_EQ1_MAX, _EQ2_MAX, _EQ4_MAX, _EQ5_MAX]:
        for vecs in d.values():
            flat.extend(vecs)
    for level_dict in _EQ3EQ6_MAX.values():
        for vecs in level_dict.values():
            flat.extend(vecs)
    for vec in flat:
        for pair in vec.rstrip("/").split("/"):
            abbrev, val = pair.split(":")
            assert val in _ALL_ALLOWED[abbrev], (
                f"{abbrev}:{val} not in _ALL_ALLOWED"
            )


# ---------------------------------------------------------------------------
# Scoring tests — vectors and expected scores from spec examples page
# https://www.first.org/cvss/v4.0/examples
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vector,expected",
    [
        # Base only (E absent → E:X → treated as Attacked, Spec §7.4)
        # CVE-2022-41741 (NGINX mp4 module)
        (
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            7.3,
        ),
        # CVE-2020-3549 (Cisco Firepower)
        (
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            7.7,
        ),
        # CVE-2023-3089 (OpenShift FIPS)
        (
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N",
            8.3,
        ),
        # CVE-2021-44714 (Adobe Reader)
        (
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            4.6,
        ),
        # CVE-2022-24682 (Zimbra Calendar XSS)
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
            5.1,
        ),
        # CVE-2022-22186 (Juniper EX4650)
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
            6.9,
        ),
        # CVE-2023-21989 (Oracle VirtualBox)
        (
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
            5.9,
        ),
        # CVE-2020-3947 (VMware Workstation/Fusion)
        (
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            9.4,
        ),
        # CVE-2023-48228 (authentik PKCE)
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H",
            9.3,
        ),
        # CVE-2018-3652 (Intel DCI physical access)
        (
            "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            8.5,
        ),
        # CVE-2024-6387 (regreSSHion OpenSSH — examples page
        # shows E:P explicitly)
        (
            "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P",
            8.2,
        ),
        # CVE-2013-6014 (Juniper Proxy ARP)
        (
            "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H",
            6.4,
        ),
        # With Threat metric
        # CVE-2020-3549 + E:U (Cisco Firepower, Exploit Unreported)
        (
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
            5.2,
        ),
        # CVE-2014-0160 Heartbleed with E:A
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A",
            8.7,
        ),
        # CVE-2021-44228 Log4Shell with E:A
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
            9.3,
        ),
    ],
)
def test_score(vector: str, expected: float) -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(vector).parsed)
    assert cvs.base_score == expected, (
        f"Vector: {vector}\nExpected: {expected}, got: {cvs.base_score}"
    )


def test_version_property() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_VALID_BASE).parsed)
    assert cvs.version == "4.0"


def test_base_vulnerability_vector_roundtrip() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_VALID_BASE).parsed)
    assert cvs.base_vulnerability_vector.startswith("CVSS:4.0/")
    assert "AV:N" in cvs.base_vulnerability_vector


def test_base_metrics_count() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_VALID_BASE).parsed)
    assert len(cvs.base_metrics()) == 11


def test_threat_metrics() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_VALID_BASE).parsed)
    metrics = cvs.threat_metrics()
    assert len(metrics) == 1
    assert metrics[0].short_name == "E"


def test_environmental_metrics() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_VALID_BASE).parsed)
    metrics = cvs.environmental_metrics()
    assert len(metrics) == 14
    assert metrics[0].short_name == "CR"


def test_supplemental_metrics() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_VALID_BASE).parsed)
    metrics = cvs.supplemental_metrics()
    assert len(metrics) == 6
    assert metrics[0].short_name == "S"


def test_cvss40_satisfies_cvss40result_protocol() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_VALID_BASE).parsed)
    assert isinstance(cvs, CVSS40Result)


def test_macro_vector_log4shell() -> None:
    vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(vec).parsed)
    mv = cvs.macro_vector
    assert mv.eq1 == 0  # AV:N + PR:N + UI:N → most severe
    assert mv.eq5 == 0  # E:A (Attacked) → most severe


def test_eq3_uses_modified_metrics() -> None:
    # Regression: EQ3 must classify by *effective* VC/VI/VA, i.e. the
    # Modified Base metrics override the base value (Spec §7.5), exactly
    # like EQ4 and EQ6. A vector whose effective severity comes from
    # MVC/MVI must score identically to its base-only equivalent.
    base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
    env = (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        "/MVC:H/MVI:H"
    )
    cvs_base = CommonVulnerabilityScore40(VulnerabilityVector40(base).parsed)
    cvs_env = CommonVulnerabilityScore40(VulnerabilityVector40(env).parsed)
    assert cvs_env.macro_vector.eq3 == 0
    assert cvs_env.macro_vector == cvs_base.macro_vector
    assert cvs_env.base_score == cvs_base.base_score


def test_macro_vector_satisfies_protocol() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_VALID_BASE).parsed)
    assert isinstance(cvs, CVSS40Result)
    mv = cvs.macro_vector
    assert len(mv) == 6
    assert all(isinstance(x, int) for x in mv)


def test_metrics_are_lazily_constructed() -> None:
    cvs = CommonVulnerabilityScore40(VulnerabilityVector40(_VALID_BASE).parsed)
    assert "_metrics" not in cvs.__dict__
    _ = cvs.base_score  # scoring does not trigger metric construction
    assert "_metrics" not in cvs.__dict__
    _ = cvs.base_metrics()
    assert "_metrics" in cvs.__dict__
