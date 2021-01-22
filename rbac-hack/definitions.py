from export_assets import tag, user, group


group_definitions = [
    {
        'name': 'External Agents',
        'uuids': list(
            tag['Location']['External'] and tag['Source']['Agent']
        ),
        'principals': [
            ('user', user['agroome@tenable.com']),
            ('group', group['Auditors'])
        ]
    },
    {
        'name': 'Access Group',
        'uuids': list(
            tag['Location']['Internal'] - tag['Source']['Agent']
        ),
        'principals': [
            ('user', user['agroome@tenable.com']),
            ('group', group['Auditors'])
        ]
    }
]