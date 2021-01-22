#!/usr/bin/env python
# coding: utf-8

# exmaple metrics I mocked up a while back... 

# notes:
# - These examples use the pytenable library (pip install pytenable) https://pytenable.readthedocs.io/
#
# - The scan.export endpoint can be used to apply filters for individual scans. These example use a BytesIO object
#   which loads the results into memory. For larger scans you may want write to a file as described in the docs.
#
# - The workbench endpoint is limited to 5000 results. For larger queries of cumulative data (not individual scan),
#   the export endpoint is recommended i.e. tio.exports.vulns or tio.exports.assets.
#
# - These examples use the most recent scan as the 'monthly' scan. If you want a historical scan you will need to
#   pass the scan_id and the history_id to the export call or results call.
#



def filter_cumulative_export():
    vulns_iter = tio.exports.vulns(filters=['severity', 'neq', 'Info'])
    vulns = list(vulns_iter)

    def cve_match(v, query_cve):
        if type(query_cve) is list:
            return ','.join(v['plugin'].get('cve', [])) == ','.join(query_cve)
        else:
            return query_cve in v['plugin'].get('cve', [])

    query_cve = ['CVE-2017-0144']
    cves = sum(cve_match(v, query_cve) for v in vulns)

    query_cve = [
        'CVE-2019-0708', 'CVE-2019-1181', 'CVE-2019-1182', 'CVE-2019-1222',
        'CVE-2019-1223', 'CVE-2019-1224', 'CVE-2019-1225', 'CVE-2019-1226'
    ]
    cves = sum(cve_match(v, query_cve) for v in vulns)


from datetime import datetime
import pandas as pd
import io
import re

# PLUGIN YOUR KEYS HERE
tio = TenableIO(ACCESS_KEY, SECRET_KEY)

full_scan_regex = re.compile('^Credentialed checks : yes')


def get_summary_plugins(scan):
    with io.BytesIO() as f_obj:
        tio.scans.export(scan['id'], filters=[('plugin.id', 'eq', '19506')], format='csv', fobj=f_obj)
        scanned_assets = pd.read_csv(f_obj, index_col='Asset UUID', usecols=['Asset UUID', 'Plugin Output'])

    def is_full_scan(plugin_output):
        return re.search('^Credentialed checks : yes', plugin_output, re.MULTILINE) is not None

    # create 'full_scan' column with boolean values based on 'Plugin Output'
    scanned_assets['full_scan'] = scanned_assets['Plugin Output'].map(is_full_scan)
    return scanned_assets


def get_90_day_vulns(scan):
    results = tio.scans.results(scan['id'])
    scan_timestamp = results['info']['timestamp']

    # create date filter
    num_seconds = 24 * 60 * 60 * 90
    date_str_90_days = datetime.fromtimestamp(scan_timestamp - num_seconds).strftime('%m/%d/%Y')
    date_filter = ('plugin.attributes.vuln_publication_date', 'date-lt', date_str_90_days)

    with io.BytesIO() as f_obj:
        tio.scans.export(scan['id'], format='csv', fobj=f_obj, filters=[date_filter])
        vulns = pd.read_csv(f_obj, usecols=['Asset UUID', 'Risk'])

    # Don't count INFO severity
    vulns = vulns[vulns.Risk != 'None'].fillna(0)
    vulns['count'] = 1

    return vulns.groupby(by='Asset UUID').agg('sum')[['count']]


# count vulns in state
def count_vulns(scan, state):
    with io.BytesIO() as f_obj:
        tio.scans.export(scan['id'], format='csv', filters=[('tracking.state', 'eq', state)], fobj=f_obj)
        vulns = pd.read_csv(f_obj, low_memory=False)

    return len(vulns[vulns.Risk != 'None'])


def compute_tab1_metrics(scan_names):
    scans = [scan for scan in tio.scans.list() if scan['name'] in scan_names]

    assets = pd.concat([get_summary_plugins(scan) for scan in scans])
    vulns_90_day = pd.concat([get_90_day_vulns(scan) for scan in scans])
    vulns_90_day['full_scan'] = [assets['full_scan'][uuid] for uuid in vulns_90_day.index]

    inventoried_assets = len(assets)
    full_access_assets = len(assets[assets.full_scan])

    total_active = sum(count_vulns(scan, 'Active') for scan in scans)
    total_fixed = sum(count_vulns(scan, 'Fixed') for scan in scans)

    overall_worst_case = vulns_90_day['count'].max()
    worst_case_full_access = vulns_90_day[vulns_90_day['full_scan'] == True]['count'].max()
    local_worst_case = overall_worst_case if full_access_assets == 0 else worst_case_full_access

    metrics = {
        'Full access assets': full_access_assets,
        'Inventoried assets': inventoried_assets,
        '% Access': full_access_assets / inventoried_assets * 100,
        'No Full access assets': inventoried_assets - full_access_assets,
        'Full access vulns': vulns_90_day[vulns_90_day.full_scan]['count'].sum(),
        'Active vulns': total_active,
        'Fixed vulns': total_fixed,
        '% Remediation effort': total_fixed / total_active * 100,
        'Local worst case': local_worst_case
    }

    return metrics


def main():
    # groups of scans that will be aggregated into one set of metrics
    # scan_groups Dictionary:
    # indexed by the name of the Asset group
    scan_groups = {
        'Office': [
                'Office - Agent Scan',
                'Office - Network Scan - Auth',
            ]
    }

    metrics = {group: compute_tab1_metrics(scans) for group, scans in scan_groups.items()}
    # metrics = {group: scans for group, scans in scan_groups.items()}
    print(metrics)


if __name__ == '__main__':
    main()
