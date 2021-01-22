#!/usr/bin/env python

from export_assets import tio, assets, access_groups
from definitions import group_definitions

def update_groups():
    for access_group in group_definitions:
        ip_addresses = []
        for uuid in access_group['uuids']:
            ip_addresses.extend(assets[uuid]['ipv4s'])
        if access_group['name'] in access_groups:
            group_id = access_groups[access_group['name']]
            plural = "" if len(ip_addresses) == 1 else "s"
            print(f"updating {access_group['name']} with {len(ip_addresses)} asset{plural}")
            tio.access_groups.edit(
                group_id, rules=[('ipv4', 'eq', ip_addresses)], 
                principals=access_group['principals']
            )
        else:
            plural = "" if len(ip_addresses) == 1 else "s"
            print(f"creating {access_group['name']} with {len(ip_addresses)} asset{plural}")
            tio.access_groups.create(
                access_group['name'], [('ipv4', 'eq', ip_addresses)], 
                principals=access_group['principals']
            )


if __name__ == '__main__':
    update_groups()