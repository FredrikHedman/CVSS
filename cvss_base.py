#!/usr/bin/env python3
#
# Author: Fredrik Hedman <fredrik.hedman@noruna.se>
# Version: 1.15
# LICENSE: MIT LICENSE
#
"""Base class for CVSS metrics.

This class is an abstract interface.  To create a concrete class
inhert from this class and implement the follwoing methods:

   * version : CVSS version string
   * base_fcn(impact) : Base Score
   * temporal_fcn(base_score) : Temporal Score
   * environmental_fcn(adjusted_temporal_score) :  Environmental Score
   * impact : float
   * adjusted_impact : float
   * exploitability : float
   * base_metrics : list of base metrics
   * temporal_metrics : list of temporal metrics
   * environmental_metrics : list of environmental metrics
   * base_vector : string
   * temporal_vector : string
   * environmental_vector : string

"""
class CVSS:
    @property
    def version(self):
        return str()

    @property
    def base_score(self):
        return round(self.base_fcn(self.impact), ndigits=1)

    @property
    def adjusted_base_score(self):
        return round(self.base_fcn(self.adjusted_impact), ndigits=1)

    @property
    def temporal_score(self):
        return round(self.temporal_fcn(self.base_score), ndigits=1)

    @property
    def adjusted_temporal_score(self):
        return round(self.temporal_fcn(self.adjusted_base_score), ndigits=1)

    @property
    def environmental_score(self):
        return round(self.environmental_fcn(self.adjusted_temporal_score), ndigits=1)

    @property
    def impact(self):
        return float()

    @property
    def adjusted_impact(self):
        return float()

    @property
    def exploitability(self):
        return float()

    def base_metrics(self):
        return None

    def temporal_metrics(self):
        return None

    def environmental_metrics(self):
        return None

    @property
    def base_vulnerability_vector(self):
        return self.base_vector

    @property
    def temporal_vulnerability_vector(self):
        return self.temporal_vector

    @property
    def environmental_vulnerability_vector(self):
        return self.environmental_vector
