#!/usr/bin/env python3

from utils.keys import keys
from itertools import combinations
from netaddr import IPNetwork, IPSet, IPRange


def inject_ip_set(zone):
    ip_set = IPSet()
    for item in zone['ipList'].split(','):
        i0, _, i1 = item.partition('-')
        ip_set.add(IPRange(i0, i1)) if i1 else ip_set.add(i0)
    zone['ip_set'] = ip_set
    return zone


def not_default(zone):
    return zone['ip_set'] != IPSet(IPNetwork('0.0.0.0/0'))


def zone_overlap(z1, z2):
    return z1['ip_set'] & z2['ip_set']


tsc = keys.use('tsc-admin')
zones = filter(not_default, map(inject_ip_set, tsc.scan_zones.list()))
zone_lookup = {z['id']: z for z in zones}

for z1, z2 in combinations(zone_lookup, 2):
    zone_one, zone_two = zone_lookup[z1], zone_lookup[z2]
    overlap = zone_overlap(zone_one, zone_two)
    if overlap :
        print(f'{zone_one["name"]} intersects {zone_two["name"]}: {overlap}')

