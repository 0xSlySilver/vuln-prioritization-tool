""" 
Vulnerability Prioritization Tool

- Normalizes severity into numeric risk
- Identifies SLA violations or vulnerability age
- Determines asset is externally facing by hostname
- Computes weighted priority score

Intended for vulnerability management automation workflows.
"""

import pandas as pd 
from pathlib import Path

CRITICAL_SLA_DAYS = 7
HIGH_SLA_DAYS = 30
UNTOUCHED_VULN_DAYS = 40
EXTERNAL_MULTIPLIER = 3.0
SLA_MULTIPLIER = 0.5
AGE_MULTIPLIER = 1.0

# Opens raw vulnerability data in Documents folder.
REPORT_DIR = Path.home() / 'Documents'
VULN_FILE = Path.home() / 'Documents' / 'raw_vulns.csv'
df = pd.read_csv(VULN_FILE)

# Assigns a number to the vulnerability severity.
severity_map = {
    'Critical': 4,
    'High': 3,
    'Medium': 2,
    'Low': 1
}

# Creates new RiskScore Column with values from severity_map.
df['RiskScore'] = df['Severity'].map(severity_map).fillna(0)

# Creates df_filtered variable that only has vulns that are Open.
df_filtered = df[ (df['Severity'].isin(['Critical', 'High', 'Medium', 'Low'])) & (df['Status'] == 'Open') ].copy()

# Sorts by oldest to newest.
df_filtered.sort_values(by='Discovered', ascending=False, inplace=True)

# Converts Discovered column to a timedelta type then subtracts it by specified timestamp.
today = pd.Timestamp.today()
df_filtered['Discovered'] = pd.to_datetime(df_filtered['Discovered'])
df_filtered['DaysOpen'] = (today - df_filtered['Discovered']).dt.days

# Determines SLA violations by comparing DaysOpen column to integer representing maximum acceptable days. Then assigns True or False.
df_filtered['SLA Violation'] = False

df_filtered.loc[
    (df_filtered['Severity'] == 'Critical') & (df_filtered['DaysOpen'] > CRITICAL_SLA_DAYS),
    'SLA Violation'
] = True

df_filtered.loc[
    (df_filtered['Severity'] == 'High') & (df_filtered['DaysOpen'] > HIGH_SLA_DAYS),
    'SLA Violation'
] = True

# Determines if the device is externally facing if the hostname contains web. 
df_filtered['ExternallyFacing'] = False

df_filtered.loc[
    df_filtered['Host'].str.contains(r'web', case=False, na=False),
    'ExternallyFacing'
] = True

# Creates PriorityScoreRaw column and performs ranking logic/arithmetic.
df_filtered['PriorityScoreRaw'] = df_filtered['RiskScore'] * df_filtered['CVSS']
df_filtered['PriorityScoreRaw'] *= 1 + EXTERNAL_MULTIPLIER * (df_filtered['ExternallyFacing']).astype(int) # 100% boost if device is externally facing
df_filtered['PriorityScoreRaw'] *= 1 + SLA_MULTIPLIER * df_filtered['SLA Violation'].astype(int)  # 50% boost if device is in violation of SLA
df_filtered['PriorityScoreRaw'] *= AGE_MULTIPLIER + (df_filtered['DaysOpen'] >= UNTOUCHED_VULN_DAYS).astype(int)   # 100% boost if vulnerability is 40 days or older 


# Sort by PriorityScoreRaw in descending order. If there are ties in PriorityScoreRaw, DaysOpen will sort descending to break the tie.
df_filtered.sort_values(
    by=['PriorityScoreRaw', 'DaysOpen'], 
    ascending=[False, False], 
    inplace=True
)

# Creates PriorityScore column and increments by 1
df_filtered['PriorityScore'] = range(1, len(df_filtered) + 1)

# Removing unneeded/irrelevant columns.
df_filtered.drop('RiskScore', axis=1, inplace=True)
df_filtered.drop('PriorityScoreRaw', axis=1, inplace=True)
df_filtered.drop('ExternallyFacing', axis=1, inplace=True)

# Writes to new file.
df_filtered.to_csv(REPORT_DIR / 'vuln_triage_report.csv', index=False)