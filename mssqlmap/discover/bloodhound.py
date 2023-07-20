from typing import Any

from requests.auth import HTTPBasicAuth
import requests

from mssqlmap.model import DatabaseServicePrincipal

DEFAULT_SPNS = 'MSSQLSVC MSSERVERCLUSTER MSCLUSTERVIRTUALSERVER MSSERVERCLUSTERMGMTAPI'.split(' ')


def get_spns(url: str, username: str, password: str, prefixes: list[str]|None = None) -> set[DatabaseServicePrincipal]:
    prefixes = prefixes or DEFAULT_SPNS
    filter = ' OR '.join(f'toUpper(s) STARTS WITH "{p}/"' for p in prefixes)
    objects = query(url, username, password, f'MATCH (o) WHERE o.enabled AND ANY (s IN o.serviceprincipalnames WHERE {filter}) RETURN o')
    result = set()
    for obj in objects:
        for spn in obj['serviceprincipalnames']:
            # get prefix
            pos = spn.find('/')
            assert pos != -1, f'invalid spn: {spn}'
            prefix = spn[:pos].upper()
            if prefix not in prefixes:
                continue
            # remove prefix
            spn = spn[pos + 1:]
            # remove optional port suffix
            pos = spn.rfind(':')
            if pos == -1:
                port = 1433
            else:
                try:
                    port = int(spn[pos + 1:])
                except Exception:
                    # spn end with instance name instead of port
                    continue
                spn = spn[:pos]
            # append domain if missing
            if '.' not in spn:
                spn = f'{spn}.{obj["domain"]}'
            result.add(DatabaseServicePrincipal(host=spn.lower(), port=port))
    return result


def query(url: str, username: str, password: str, statement: str) -> list[Any]:
    response = requests.post(
        f'{url}/db/neo4j/tx',
        auth=HTTPBasicAuth(username, password),
        json=dict(statements=[dict(statement=statement)]),
    )
    data = response.json()
    error = '\n'.join(e['message'] for e in data['errors'])
    if error:
        raise RuntimeError(error)
    return [row for result in data['results'] for rows in result['data'] for row in rows['row']]
