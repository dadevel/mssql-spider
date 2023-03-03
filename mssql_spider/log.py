from typing import Any
from impacket.tds import SQLErrorException

from rich.console import Console
from rich.highlighter import NullHighlighter
from rich.style import Style
from rich.text import Text

console = Console(highlighter=NullHighlighter())


def spider_status(client, status: str, path: str = '', message: str|None = None) -> None:
    match status:
        case 'pwned':
            style = Style(color='green', bold=True)
        case 'allowed'|'repeated':
            style = Style(color='green')
        case 'denied':
            style = Style(color='yellow')
        case _:
            style = Style()
    write(
        f'{client.connection.server}:{client.connection.port}',
        client.path + path,
        'spider',
        dict(status=Text(status, style=style), message=message),
    )


def module_result(client, module: str, result: dict[str, Any]) -> None:
    write(
        f'{client.connection.server}:{client.connection.port}',
        client.path,
        module,
        result,
    )


def general_error(target: tuple[str, int], module: str, exception: Exception) -> None:
    error(
        f'{target[0]}:{target[1]}',
        None,
        module,
        exception,
    )


def module_error(client, module: str, exception: Exception) -> None:
    error(
        f'{client.connection.server}:{client.connection.port}',
        client.path,
        module,
        exception,
    )


def error(target: str, path: str|None, module: str, error: Exception) -> None:
    write(
        target,
        path,
        module,
        dict(status=Text('error', style=Style(color='red')), message=str(error).removeprefix('ERROR: ').removeprefix('Line 1: ') if isinstance(error, SQLErrorException) else str(error)),
    )


def write(target: str, path: str|None, module: str, message: dict[str, Any]) -> None:
    prefix = [path, module] if path else [module]
    console.print(
        Text(target, style=Style(color='blue')),
        *prefix,
        _format_result(message),
    )


def _format_result(data: dict[str, Any]) -> Text:
    result = Text()
    for key, value in data.items():
        if value is None:
            continue
        result += Text(f'{key}=')
        result += value if isinstance(value, Text) else Text(str(value))
        result += ' '
    return result[:-1]
