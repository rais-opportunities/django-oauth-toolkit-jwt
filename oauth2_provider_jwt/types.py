from typing import Any, Dict, Sequence, Union

#: Defines the structure for an issuer's settings defined in settings.py
IssuerSettingsDict = Dict[str, Union[None, str, Dict[str, Any], Sequence[str]]]
