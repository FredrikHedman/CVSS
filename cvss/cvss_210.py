#!/usr/bin/env python
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# VERSION: 1.20.1
# LICENSE: MIT LICENSE
#

"""Calculate CVSS metrics v 2.10."""

from typing import override

from .cvss_base import CVSS
from .metric import Metric


class CommonVulnerabilityScore(CVSS):
    """A concrete implementation of CVSS."""

    def __init__(self, metrics_seq: list[Metric]) -> None:
        self.__metrics: dict[str, Metric] = {}
        for m in metrics_seq:
            self.__metrics[m.short_name] = m
        error_message = "Metric short name collision"
        assert len(self.__metrics) == len(metrics_seq), error_message

    def __getitem__(self, idx: str) -> Metric:
        return self.__metrics[idx]

    @property
    @override
    def version(self) -> str:
        return "2.10"

    @override
    def base_fcn(self, impact: float) -> float:
        score = 0.6 * impact + 0.4 * self.exploitability - 1.5
        score *= self.fcn(impact)
        return score

    @override
    def temporal_fcn(self, score: float) -> float:
        score *= float(self["E"])
        score *= float(self["RL"])
        score *= float(self["RC"])
        return score

    @override
    def environmental_fcn(self, adjusted_temporal_score: float) -> float:
        score = adjusted_temporal_score
        score += (10.0 - adjusted_temporal_score) * float(self["CDP"])
        score *= float(self["TD"])
        return score

    @property
    @override
    def impact(self) -> float:
        conf_impact = float(self["C"])
        integ_impact = float(self["I"])
        avail_impact = float(self["A"])
        return self.impact_fcn(conf_impact, integ_impact, avail_impact)

    @property
    @override
    def adjusted_impact(self) -> float:
        conf_impact = float(self["C"]) * float(self["CR"])
        integ_impact = float(self["I"]) * float(self["IR"])
        avail_impact = float(self["A"]) * float(self["AR"])
        result = self.impact_fcn(conf_impact, integ_impact, avail_impact)
        return min(10.0, result)

    @property
    @override
    def exploitability(self) -> float:
        res = 20.0
        res *= float(self["AV"])
        res *= float(self["AC"])
        res *= float(self["Au"])
        return res

    def impact_fcn(
        self,
        conf_impact: float,
        integ_impact: float,
        avail_impact: float,
    ) -> float:
        result = 1 - (
            (1 - conf_impact) * (1 - integ_impact) * (1 - avail_impact)
        )
        result *= 10.41
        return result

    def fcn(self, impact: float) -> float:
        val = 1.176
        if impact == 0:
            val = 0.0
        return val

    @override
    def base_metrics(self) -> list[Metric]:
        vv = ["AV", "AC", "Au", "C", "I", "A"]
        return [self[v] for v in vv]

    @property
    @override
    def base_vector(self) -> str:
        vv = ["AV", "AC", "Au", "C", "I", "A"]
        return "/".join(f"{v}:{self[v]}" for v in vv)

    @override
    def temporal_metrics(self) -> list[Metric]:
        vv = ["E", "RL", "RC"]
        return [self[v] for v in vv]

    @property
    @override
    def temporal_vector(self) -> str:
        vv = ["E", "RL", "RC"]
        return "/".join(f"{v}:{self[v]}" for v in vv)

    @override
    def environmental_metrics(self) -> list[Metric]:
        vv = ["CDP", "TD", "CR", "IR", "AR"]
        return [self[v] for v in vv]

    @property
    @override
    def environmental_vector(self) -> str:
        vv = ["CDP", "TD", "CR", "IR", "AR"]
        return "/".join(f"{v}:{self[v]}" for v in vv)


if __name__ == "__main__":
    import doctest

    doctest.testmod()
