"""Type definitions for TunerStudio MLG binary log format."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Union

from typing_extensions import Literal, TypedDict


# ---------------------------------------------------------------------------
# Logger-field display styles
# ---------------------------------------------------------------------------

DisplayStyle = Literal[
    "Float",
    "Hex",
    "bits",
    "Date",
    "On/Off",
    "Yes/No",
    "High/Low",
    "Active/Inactive",
    "True/False",
]

BlockType = Literal["field", "marker"]


# ---------------------------------------------------------------------------
# Logger field definitions (embedded in the file header)
# ---------------------------------------------------------------------------


class LoggerFieldScalar(TypedDict):
    """A scalar (numeric) logger field definition."""

    type: int  # 0-7
    units: str
    display_style: DisplayStyle
    scale: float
    transform: float
    digits: int
    category: str


class LoggerFieldBit(TypedDict):
    """A bit-field logger field definition."""

    type: int  # 10-12
    units: str
    display_style: DisplayStyle
    bit_field_style: DisplayStyle
    bit_field_names_index: int
    bits: int
    category: str


LoggerField = Union[LoggerFieldScalar, LoggerFieldBit]


# ---------------------------------------------------------------------------
# Parsed result
# ---------------------------------------------------------------------------


class ParseResult(TypedDict):
    """The top-level result returned by :func:`ts_logs.parse`."""

    file_format: str
    format_version: int
    timestamp: datetime
    info: str
    bit_field_names: str
    fields: Dict[str, LoggerField]
    record_length: int
    records: List[Dict[str, Union[int, float, str]]]
