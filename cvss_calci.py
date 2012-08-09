""" CVSS Calculator """

import sys

# Predefined Standard Values
ACCESS_VECTOR = {'L': ['LOCAL', 0.7], 'R': ['REMOTE', 1.0]}
ACCESS_COMPLEXITY = {'H': ['HIGH', 0.8], 'L': ['LOW', 1.0]}
AUTHENTICATION = {'R': ['REQUIRED', 0.6], 'NR': ['NOT_REQUIRED', 1.0]}
CONFIDENTIALITY_IMPACT = {'N': ['NONE', 0], 'P': ['PARTIAL', 0.7],
                          'C': ['COMPLETE', 1.0]}
INTEGRITY_IMPACT = {'N': ['NONE', 0], 'P': ['PARTIAL', 0.7],
                    'C': ['COMPLETE', 1.0]}
AVAILABILITY_IMPACT = {'N': ['NONE', 0], 'P': ['PARTIAL', 0.7],
                       'C': ['COMPLETE', 1.0]}
CONF_IMPACT_BIAS = {'N': ['NORMAL', 0.333], 'C': ['CONFIDENTIALITY', 0.5],
                    'I': ['INTEGRITY', 0.25], 'A': ['AVAILABILITY', 0.25]}
INTEG_IMPACT_BIAS = {'N': ['NORMAL', 0.333], 'C': ['CONFIDENTIALITY', 0.25],
                     'I': ['INTEGRITY', 0.5], 'A': ['AVAILABILITY', 0.25]}
AVAIL_IMPACT_BIAS = {'N': ['NORMAL', 0.333], 'C': ['CONFIDENTIALITY', 0.25],
                     'I': ['INTEGRITY', 0.25], 'A': ['AVAILABILITY', 0.5]}
EXPLOITABILITY = {'U': ['UNPROVEN', 0.85], 'POC': ['PROOF_OF_CONCEPT', 0.9],
                  'F': ['FUNCTIONAL', 0.95], 'H': ['HIGH', 1.0]}
REMEDIATION_LEVEL = {'OF': ['OFFICIAL_FIX', 0.87], 'TF': ['TEMPORARY_FIX', 0.90],
                     'WA': ['WORKAROUND', 0.95], 'UA': ['UNAVAILABLE', 1.0]}
REPORT_CONFIDENCE = {'UCONF': ['UNCONFIRMED', 0.90], 'UCOR': ['UNCORROBORATED', 0.95],
                     'C': ['CONFIRMED', 1.0]}
COLLATERAL_DAMAGE_POTENTIAL = {'N': ['NONE', 0], 'L': ['LOW', 0.1],
                               'M': ['MEDIUM', 0.3], 'H': ['HIGH', 0.5]}
TARGET_DISTRIBUTION = {'N': ['NONE', 0], 'L': ['LOW', 0.25], 'M': ['MEDIUM', 0.75],
                       'H': ['HIGH', 1.0]}

METRIC_NAME = 0
METRIC_CONS = 1

# Input values - Order of metrics has to be maintained
acc_vec = None
acc_comp  =  None
auth = None
conf_impact = None
integ_impact = None
avail_impact = None
impact_bias = None
exploit = None
remed_level = None
report_conf = None
col_dam_poten = None
target_distr = None

def is_valid_input(metric_value, metric_name):
    """Check for valid input."""

    # check for valid data type
    #if type(metric_value) != str:
    #    print "Found incorrect values in the metric fields. " + \
    #    "Re-enter the metric value"
    #    return None

    # check for empty string value
    if metric_value == '':
        print "Error: No value found. Re-enter the metric value"
        return None

    # standardize the input entries
    metric_value = metric_value.upper()

    # exit from the program
    if metric_value == 'Q':
        sys.exit(0)

    # validate the string values w.r.t standard predefined values
    if metric_name == 'AV' and not ACCESS_VECTOR.has_key(metric_value) or  \
       metric_name == 'AC' and not ACCESS_COMPLEXITY.has_key(metric_value) or \
       metric_name == 'Au' and not AUTHENTICATION.has_key(metric_value) or \
       metric_name == 'C' and not CONFIDENTIALITY_IMPACT.has_key(metric_value) or \
       metric_name == 'I' and not INTEGRITY_IMPACT.has_key(metric_value) or \
       metric_name == 'A' and not AVAILABILITY_IMPACT.has_key(metric_value) or \
       metric_name == 'B' and not CONF_IMPACT_BIAS.has_key(metric_value) or \
       metric_name == 'EXP' and not EXPLOITABILITY.has_key(metric_value) or \
       metric_name == 'RL' and not REMEDIATION_LEVEL.has_key(metric_value) or \
       metric_name == 'RC' and not REPORT_CONFIDENCE.has_key(metric_value):
        print "Incorrect option for %s metric. Re-enter the metric value" % \
        (metric_name)
        return None

    return metric_value

def cvss_score(ib):
    """Calculate CVSS Score"""
    try:
        base_score = (10 * ACCESS_VECTOR[acc_vec][METRIC_CONS]
                      * ACCESS_COMPLEXITY[acc_comp][METRIC_CONS]
                      * AUTHENTICATION[auth][METRIC_CONS]
                      * ((CONFIDENTIALITY_IMPACT[conf_impact][METRIC_CONS]
                          * CONF_IMPACT_BIAS[impact_bias][METRIC_CONS])
                        + (INTEGRITY_IMPACT[integ_impact][METRIC_CONS]
                           * INTEG_IMPACT_BIAS[impact_bias][METRIC_CONS])
                        + (AVAILABILITY_IMPACT[avail_impact][METRIC_CONS]
                           * AVAIL_IMPACT_BIAS[impact_bias][METRIC_CONS])))

        temp_score = (base_score
                      * EXPLOITABILITY[exploit][METRIC_CONS]
                      * REMEDIATION_LEVEL[remed_level][METRIC_CONS]
                      * REPORT_CONFIDENCE[report_conf][METRIC_CONS])

        #env_score = (temp_score
        #             + (10 - temp_score)
        #             * COLLATERAL_DAMAGE_POTENTIAL[col_dam_poten][METRIC_CONS]
        #             * TARGET_DISTRIBUTION[target_distr][METRIC_CONS])
    except Exception, err:
        print "Error: ", err
        return 0
    return (base_score, temp_score)

def find_risk(temp_score):
    risk = ""
    if temp_score >= 0 and temp_score < 1:
        risk = "Informational"
    elif temp_score >= 1 and temp_score <= 2:
        risk = "Low"
    elif temp_score > 2 and temp_score <= 5:
        risk = "Medium"
    elif temp_score > 5 and temp_score <= 8:
        risk = "High"
    elif temp_score > 8 and temp_score <= 10:
        risk = "Critical"
    else:
        print "Invalid Temporal Score"
        return None
    return risk

if __name__ == '__main__':
    # Read the metric values from the user
    score_vector = []

    print "Enter the metric values. Enter 'q' to exit the program. " + \
    "(values are not case sensitive)"

    while acc_vec == None:
        metric_name = 'AV'
        print "\nValid Options for ACCESS_VECTOR = LOCAL:L | REMOTE:R"
        acc_vec = is_valid_input(raw_input(), metric_name)
        score_vector.append([metric_name, acc_vec])

    while acc_comp == None:
        metric_name = 'AC'
        print "\nValid Options for ACCESS_COMPLEXITY = HIGH:H | LOW:L"
        acc_comp = is_valid_input(raw_input(), metric_name)
        score_vector.append([metric_name, acc_comp])

    while auth == None:
        metric_name = 'Au'
        print "\nValid Options for AUTHENTICATION = REQUIRED:R | " + \
        "NOT_REQUIRED:NR"
        auth = is_valid_input(raw_input(), metric_name)
        score_vector.append([metric_name, auth])

    while conf_impact == None:
        metric_name = 'C'
        print "\nValid Options for CONFIDENTIALITY_IMPACT = NONE:N | " + \
        "PARTIAL:P | COMPLETE:C"
        conf_impact = is_valid_input(raw_input(), metric_name)
        score_vector.append([metric_name, conf_impact])

    while integ_impact == None:
        metric_name = 'I'
        print "\nValid Options for INTEGRITY_IMPACT = NONE:N | PARTIAL:P | " + \
        "COMPLETE:C"
        integ_impact = is_valid_input(raw_input(), metric_name)
        score_vector.append([metric_name, integ_impact])

    while avail_impact == None:
        metric_name = 'A'
        print "\nValid Options for AVAILABILITY_IMPACT = NONE:N | PARTIAL:P" + \
        " | COMPLETE:C"
        avail_impact = is_valid_input(raw_input(), metric_name)
        score_vector.append([metric_name, avail_impact])

    while impact_bias == None:
        metric_name = 'B'
        print "\nValid Options for IMPACT_BIAS = NORMAL:N | CONFIDENTIALITY:C" + \
        " | INTEGRITY:I | AVAILABILITY:A"
        impact_bias = is_valid_input(raw_input(), metric_name)
        score_vector.append([metric_name, impact_bias])

    while exploit == None:
        metric_name = 'EXP'
        print "\nValid Options for EXPLOITABILITY = UNPROVEN:U | " + \
        "PROOF_OF_CONCEPT:POC | FUNCTIONAL:F | HIGH:H"
        exploit = is_valid_input(raw_input(), metric_name)

    while remed_level == None:
        metric_name = 'RL'
        print "\nValid Options for REMEDIATION_LEVEL = OFFICIAL_FIX:OF | " + \
        "TEMPORARY_FIX:TF | WORKAROUND:WA | UNAVAILABLE:UA"
        remed_level = is_valid_input(raw_input(), metric_name)

    while report_conf == None:
        metric_name = 'RC'
        print "\nValid Options for REPORT_CONFIDENCE = UNCONFIRMED:UCONF | " + \
        "UNCORROBORATED:UCOR | CONFIRMED:C"
        report_conf = is_valid_input(raw_input(), metric_name)

    #while col_dam_poten == None:
    #    metric_name = 'CDP'
    #    print "\nValid Options for COLLATERAL_DAMAGE_POTENTIAL = NONE:N | " + \
    #    "LOW:L | MEDIUM:M | HIGH:H"
    #    col_dam_poten = is_valid_input(raw_input(), metric_name)
    #
    #while target_distr == None:
    #    metric_name = 'TD'
    #    print "\n-Valid Options for TARGET_DISTRIBUTION = NONE:N | LOW:L | " + \
    #    "MEDIUM:M | HIGH:H"
    #    target_distr = is_valid_input(raw_input(), metric_name)

    cvss_base_score, cvss_temp_score = cvss_score(impact_bias)
    base_score = round(cvss_base_score, 1)
    temp_score = round(cvss_temp_score, 1)

    risk_fact = find_risk(temp_score)

    basescore_vector = ''
    for name, value in score_vector:
        basescore_vector = basescore_vector + '%s:%s/' % (name,value)
    basescore_vector = '(%s)' % (basescore_vector.rstrip("/"))

    print "\nCVSS Temporal Score: ", temp_score
    print "\nCVSS Base Score Vector: ", basescore_vector

    print "\nCVSS Score Report: \n\
    ACCESS_VECTOR          = %s \n\
    ACCESS_COMPLEXITY      = %s \n\
    AUTHENTICATION         = %s \n\
    CONFIDENTIALITY_IMPACT = %s \n\
    INTEGRITY_IMPACT       = %s \n\
    AVAILABILITY_IMPACT    = %s \n\
    IMPACT_BIAS            = %s \n\
    EXPLOITABILITY         = %s \n\
    REMEDIATION_LEVEL      = %s \n\
    REPORT_CONFIDENCE      = %s \n\
    CVSS Base Score        = %s %s \n\
    CVSS Temporal Score    = %s \n\
    Risk factor            = %s \n\
    " %(ACCESS_VECTOR[acc_vec][METRIC_NAME],
        ACCESS_COMPLEXITY[acc_comp][METRIC_NAME],
        AUTHENTICATION[auth][METRIC_NAME],
        CONFIDENTIALITY_IMPACT[conf_impact][METRIC_NAME],
        INTEGRITY_IMPACT[integ_impact][METRIC_NAME],
        AVAILABILITY_IMPACT[avail_impact][METRIC_NAME],
        CONF_IMPACT_BIAS[impact_bias][METRIC_NAME],
        EXPLOITABILITY[exploit][METRIC_NAME],
        REMEDIATION_LEVEL[remed_level][METRIC_NAME],
        REPORT_CONFIDENCE[report_conf][METRIC_NAME],
        base_score, basescore_vector, temp_score, risk_fact)


    #print "\n\nMappings for Risk Factors \n\
    # =0    : Informational \n\
    #>=1-2  : Low \n\
    # >2-6  : Medium \n\
    # >6-9  : High \n\
    # >9-10 : Critical"


