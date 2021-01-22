from config import access_key, secret_key
from tenable.io import TenableIO
from pprint import pprint
from collections import defaultdict
import json

tio = TenableIO(access_key, secret_key)

print("running asset export")

# store values in lookup tables
assets = {asset['id']: asset for asset in tio.exports.assets()}
access_groups = {g['name']: g['id'] for g in tio.access_groups.list()}

group = {g['name']: g['uuid'] for g in tio.groups.list()}
user = {u['email']: u['uuid'] for u in tio.users.list()}

print("categorizing groups")
# creaate a set of asset uuids for each tag['key']['value']
tag = defaultdict(lambda: defaultdict(set))
for uuid, asset in assets.items():
    for t in asset['tags']:
        tag[t['key']][t['value']].add(uuid)

# group_definitions = [
#     {
#         'name': 'External Agents',
#         'uuids': list(
#             tag['Location']['External'] and tag['Source']['Agent']
#         ),
#         'principals': [
#             ('user', user['agroome@tenable.com']),
#             ('group', group['Auditors'])
#         ]
#     }
# ]

# for access_group in group_definitions:
#     ip_addresses = []
#     for uuid in access_group['uuids']:
#         ip_addresses.extend(assets[uuid]['ipv4s'])
#     if access_group['name'] in access_groups:
#         group_id = access_group['name']
#         tio.access_groups.edit(group_id, rules=[('ipv4', 'eq', ip_addresses)], principals=rule['principals'])
#     else:
#         tio.access_groups.create(access_group['name'], [('ipv4', 'eq', ip_addresses)], principals=access_group['principals'])
    
