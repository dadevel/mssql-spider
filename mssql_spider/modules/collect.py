from argparse import Namespace
from typing import Any

from mssql_spider.client import MSSQLClient


def visit(opts: Namespace, client: MSSQLClient) -> dict[str, Any]:
    raise NotImplementedError()
