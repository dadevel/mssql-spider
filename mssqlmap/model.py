from __future__ import annotations
import functools

import pydantic


class BaseModel(pydantic.BaseModel):
    class Config:
        extra = pydantic.Extra.ignore
        frozen = True
        # work around pydantic incompatibility with cached properties, see https://github.com/pydantic/pydantic/issues/1241#issuecomment-587896750
        ignored_types = (functools.cached_property,)
