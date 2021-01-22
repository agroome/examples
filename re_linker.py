#!/usr/bin/env python3 
"""
Link an agent on a system that has been re-imaged connecting back to 
the same uuid/agent_uuid.
"""
import dotenv
import os
from dateutil.parser import parse
from tenable.io import TenableIO

# once we get the previous agent_uuid we will write it to this file
UUID_FILE = '/etc/tenable_tag'

# store your keys in environment variables in a file called '.tio_env'
dotenv.load_dotenv('.tio_env')
access_key = os.environ.get('ACCESS_KEY')
secret_key = os.environ.get('SECRET_KEY')

tio = TenableIO(access_key, secret_key)

def str_to_dt(a):
    """convert date string to datetime so we can compare dates to find most recent"""
    a['created_dt'] = parse(a['created_at'])
    return a

def identify_uuid(mac):
    """use the mac to identify the most recent matching asset from agents scans"""
    assets = tio.exports.assets(sources=['NESSUS_AGENT'])
    filtered_with_dt = list(map(str_to_dt, filter(lambda a: mac in a['mac_addresses'], assets)))
    if filtered_with_dt:
        most_recent = max(filtered_with_dt, key=lambda a: a['created_dt'])
        return most_recent['id'], most_recent['agent_uuid']
    return None, None


def identify_agent_id(uuid):
    filtered = list(filter(lambda a: a['uuid'], tio.agents.list()))
    agent_record = filtered and filtered[0]
    return agent_record['id']


def main():
    mac = '02:e2:98:2d:e4:ba'

    # use the mac to identify the previously tracked uuid and agent_uuid
    uuid, agent_uuid = identify_uuid(mac)

    # use the uuid to get the agent_id which we use to unlink the agent
    if uuid is not None:
        agent_id = identify_agent_id(uuid)
        print(f'asset_uuid: {uuid}')
        print(f'agent_ID: {agent_id}')
        print(f'agent_UUID: {agent_uuid}')
        tio.agents.unlink(agent_id)
        # write the agent uuid to the UUID_FILE
        with open(UUID_FILE, 'w') as f:
            f.write(agent_uuid)
    else:
        print("asset uuid not found, it may have been linked, but not scanned")


if __name__ == '__main__':
    main()
