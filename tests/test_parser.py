"""Tests for ts_logs.parse() – TunerStudio MLG binary log parser."""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

import ts_logs
from ts_logs import FormatError, parse
from ts_logs.types import ParseResult


# ---------------------------------------------------------------------------
# Helpers to build synthetic MLG binary data
# ---------------------------------------------------------------------------

# Fixed header sizes:
#   6 (format) + 2 (version) + 4 (timestamp) + info_data_start field +
#   4 (data_begin_index) + 2 (record_length) + 2 (num_logger_fields)
# v1: info_data_start is u16 (2 bytes) → total 22 bytes
# v2: info_data_start is i32 (4 bytes) → total 24 bytes
_HEADER_FIXED_V1 = 22
_HEADER_FIXED_V2 = 24


def _build_mlg_v2(
    timestamp: int = 0,
    fields: list | None = None,
    data_blocks: list | None = None,
    info_data: str = "",
) -> bytes:
    """Build a minimal but valid v2 MLG binary blob.

    Parameters
    ----------
    timestamp : int
        UNIX timestamp to embed in the header.
    fields : list of (name, units, display_style, scale, transform, digits, category)
        Scalar field definitions. Defaults to one U16 field called "rpm".
    data_blocks : list of list of numbers
        Each inner list contains one raw value per field, in field order.
    info_data : str
        Optional info section text.
    """
    if fields is None:
        fields = [("rpm", "RPM", 0, 1.0, 0.0, 0, "")]
    if data_blocks is None:
        data_blocks = [[1500]]

    # -----------------------------------------------------------------------
    # Build logger-field definitions (type 2 = U16 scalar)
    # -----------------------------------------------------------------------
    field_bytes = b""
    for name, units, display_style_code, scale, transform, digits, category in fields:
        field_type = 2  # U16
        name_b = name.encode("latin-1").ljust(34, b"\x00")[:34]
        units_b = units.encode("latin-1").ljust(10, b"\x00")[:10]
        cat_b = category.encode("latin-1").ljust(34, b"\x00")[:34]
        field_bytes += struct.pack(">B", field_type)
        field_bytes += name_b
        field_bytes += units_b
        field_bytes += struct.pack(">B", display_style_code)
        field_bytes += struct.pack(">f", scale)
        field_bytes += struct.pack(">f", transform)
        field_bytes += struct.pack(">B", digits)
        field_bytes += cat_b  # v2 category (34 bytes)

    num_fields = len(fields)
    logger_field_length = 89  # v2

    # -----------------------------------------------------------------------
    # Compute header offsets
    # -----------------------------------------------------------------------
    fields_start = _HEADER_FIXED_V2
    fields_size = num_fields * logger_field_length
    bitfield_names = b""  # no bit fields
    info_data_start = fields_start + fields_size + len(bitfield_names)
    info_b = info_data.encode("latin-1")
    # data begin index comes right after info section;
    # subtract 1 for the NUL sentinel byte that terminates the info section
    data_begin_index = info_data_start + len(info_b) + 1

    # record length: sum of field sizes (U16 = 2 bytes each)
    record_length = num_fields * 2

    # -----------------------------------------------------------------------
    # Build header
    # -----------------------------------------------------------------------
    header = b"MLVLG\x00"
    header += struct.pack(">h", 2)           # format version
    header += struct.pack(">i", timestamp)   # unix timestamp
    header += struct.pack(">i", info_data_start)
    header += struct.pack(">i", data_begin_index)
    header += struct.pack(">H", record_length)
    header += struct.pack(">H", num_fields)

    # -----------------------------------------------------------------------
    # Build data blocks
    # -----------------------------------------------------------------------
    data_section = b""
    for block_idx, block_values in enumerate(data_blocks):
        data_section += struct.pack(">B", 0)               # block type: field
        data_section += struct.pack(">B", block_idx & 0xFF)  # counter
        data_section += struct.pack(">H", block_idx * 10)   # timestamp (relative)
        for val in block_values:
            data_section += struct.pack(">H", int(val))     # U16 values
        data_section += struct.pack(">B", 0)               # CRC placeholder

    # -----------------------------------------------------------------------
    # Assemble
    # -----------------------------------------------------------------------
    return header + field_bytes + bitfield_names + info_b + b"\x00" + data_section


def _build_mlg_v1(
    fields: list | None = None,
    data_blocks: list | None = None,
) -> bytes:
    """Build a minimal but valid v1 MLG binary blob.

    The v1 header differs from v2:
    - ``info_data_start`` is encoded as a u16 (2 bytes) instead of i32 (4 bytes).
    - Logger field records are 55 bytes each (no category field).
    """
    if fields is None:
        fields = [("rpm", "RPM", 0, 1.0, 0.0, 0)]
    if data_blocks is None:
        data_blocks = [[2000]]

    # -----------------------------------------------------------------------
    # Build logger-field definitions (v1, 55 bytes each, no category)
    # -----------------------------------------------------------------------
    field_bytes = b""
    for name, units, display_style_code, scale, transform, digits in fields:
        field_type = 2  # U16
        name_b = name.encode("latin-1").ljust(34, b"\x00")[:34]
        units_b = units.encode("latin-1").ljust(10, b"\x00")[:10]
        field_bytes += struct.pack(">B", field_type)
        field_bytes += name_b
        field_bytes += units_b
        field_bytes += struct.pack(">B", display_style_code)
        field_bytes += struct.pack(">f", scale)
        field_bytes += struct.pack(">f", transform)
        field_bytes += struct.pack(">B", digits)
        # no category in v1

    num_fields = len(fields)
    logger_field_length = 55  # v1

    # -----------------------------------------------------------------------
    # Compute header offsets
    # -----------------------------------------------------------------------
    fields_start = _HEADER_FIXED_V1
    fields_size = num_fields * logger_field_length
    bitfield_names = b""
    info_data_start = fields_start + fields_size + len(bitfield_names)
    data_begin_index = info_data_start + 1  # NUL sentinel

    record_length = num_fields * 2  # U16 values

    # -----------------------------------------------------------------------
    # Build header (v1 uses u16 for info_data_start)
    # -----------------------------------------------------------------------
    header = b"MLVLG\x00"
    header += struct.pack(">h", 1)                    # format version 1
    header += struct.pack(">i", 0)                    # unix timestamp
    header += struct.pack(">H", info_data_start)      # u16 in v1!
    header += struct.pack(">i", data_begin_index)
    header += struct.pack(">H", record_length)
    header += struct.pack(">H", num_fields)

    # -----------------------------------------------------------------------
    # Build data blocks
    # -----------------------------------------------------------------------
    data_section = b""
    for block_idx, block_values in enumerate(data_blocks):
        data_section += struct.pack(">B", 0)
        data_section += struct.pack(">B", block_idx & 0xFF)
        data_section += struct.pack(">H", block_idx * 10)
        for val in block_values:
            data_section += struct.pack(">H", int(val))
        data_section += struct.pack(">B", 0)  # CRC

    return header + field_bytes + bitfield_names + b"\x00" + data_section


def _build_mlg_v2_marker(message: str = "test marker") -> bytes:
    """Build a v2 MLG with a single marker block."""
    fields_size = 89  # 1 field at 89 bytes each
    info_data_start = _HEADER_FIXED_V2 + fields_size
    data_begin_index = info_data_start + 1  # NUL sentinel byte

    header = b"MLVLG\x00"
    header += struct.pack(">h", 2)
    header += struct.pack(">i", 0)
    header += struct.pack(">i", info_data_start)
    header += struct.pack(">i", data_begin_index)
    header += struct.pack(">H", 2)   # record_length (1x U16)
    header += struct.pack(">H", 1)   # 1 field

    name_b = b"afr\x00" + b"\x00" * 30
    units_b = b"lambda\x00" + b"\x00" * 3
    cat_b = b"\x00" * 34
    field_bytes = struct.pack(">B", 2)  # U16
    field_bytes += name_b + units_b
    field_bytes += struct.pack(">B", 0)       # display style
    field_bytes += struct.pack(">f", 1.0)     # scale
    field_bytes += struct.pack(">f", 0.0)     # transform
    field_bytes += struct.pack(">B", 2)       # digits
    field_bytes += cat_b

    # sentinel
    sentinel = b"\x00"

    # marker block
    msg_b = message.encode("latin-1").ljust(50, b"\x00")[:50]
    marker = struct.pack(">B", 1)   # block type: marker
    marker += struct.pack(">B", 0)  # counter
    marker += struct.pack(">H", 0)  # timestamp
    marker += msg_b

    return header + field_bytes + sentinel + marker


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestParseInputTypes:
    """parse() should accept bytes, str path, and Path."""

    def test_accepts_bytes(self):
        data = _build_mlg_v2()
        result = parse(data)
        assert isinstance(result, dict)

    def test_accepts_str_path(self, tmp_path):
        data = _build_mlg_v2()
        p = tmp_path / "test.mlg"
        p.write_bytes(data)
        result = parse(str(p))
        assert isinstance(result, dict)

    def test_accepts_path_object(self, tmp_path):
        data = _build_mlg_v2()
        p = tmp_path / "test.mlg"
        p.write_bytes(data)
        result = parse(p)
        assert isinstance(result, dict)

    def test_rejects_invalid_type(self):
        with pytest.raises(TypeError):
            parse(12345)  # type: ignore[arg-type]


class TestParseResultStructure:
    """Returned TypedDict should have the expected keys and types."""

    def setup_method(self):
        self.result: ParseResult = parse(_build_mlg_v2(timestamp=1_700_000_000))

    def test_has_file_format(self):
        assert self.result["file_format"] == "MLVLG"

    def test_has_format_version(self):
        assert self.result["format_version"] == 2

    def test_timestamp_is_datetime(self):
        assert isinstance(self.result["timestamp"], datetime)

    def test_timestamp_value(self):
        dt = datetime.fromtimestamp(1_700_000_000, tz=timezone.utc)
        assert self.result["timestamp"] == dt

    def test_has_fields_list(self):
        assert isinstance(self.result["fields"], list)

    def test_has_records_list(self):
        assert isinstance(self.result["records"], list)

    def test_has_info_string(self):
        assert isinstance(self.result["info"], str)

    def test_has_bit_field_names_string(self):
        assert isinstance(self.result["bit_field_names"], str)


class TestFieldDefinitions:
    """Logger field definitions should be parsed correctly."""

    def setup_method(self):
        self.result: ParseResult = parse(
            _build_mlg_v2(
                fields=[("rpm", "RPM", 0, 2.0, 100.0, 1, "Engine")],
                data_blocks=[[3000]],
            )
        )

    def test_num_fields(self):
        assert len(self.result["fields"]) == 1

    def test_field_name(self):
        assert self.result["fields"][0]["name"] == "rpm"

    def test_field_units(self):
        assert self.result["fields"][0]["units"] == "RPM"

    def test_field_display_style(self):
        assert self.result["fields"][0]["display_style"] == "Float"

    def test_field_scale(self):
        assert abs(self.result["fields"][0]["scale"] - 2.0) < 1e-5  # type: ignore[typeddict-item]

    def test_field_transform(self):
        assert abs(self.result["fields"][0]["transform"] - 100.0) < 1e-5  # type: ignore[typeddict-item]

    def test_field_digits(self):
        assert self.result["fields"][0]["digits"] == 1  # type: ignore[typeddict-item]

    def test_field_category(self):
        assert self.result["fields"][0]["category"] == "Engine"  # type: ignore[typeddict-item]


class TestDataRecords:
    """Data records should be parsed with the correct field values."""

    def setup_method(self):
        self.result: ParseResult = parse(
            _build_mlg_v2(
                fields=[
                    ("rpm", "RPM", 0, 1.0, 0.0, 0, ""),
                    ("map", "kPa", 0, 1.0, 0.0, 0, ""),
                ],
                data_blocks=[[1500, 101], [2000, 95]],
            )
        )

    def test_record_count(self):
        assert len(self.result["records"]) == 2

    def test_record_block_type(self):
        assert self.result["records"][0]["block_type"] == "field"

    def test_record_has_timestamp(self):
        assert "relative_timestamp" in self.result["records"][0]

    def test_first_record_rpm(self):
        assert self.result["records"][0]["rpm"] == 1500

    def test_first_record_map(self):
        assert self.result["records"][0]["map"] == 101

    def test_second_record_rpm(self):
        assert self.result["records"][1]["rpm"] == 2000

    def test_second_record_map(self):
        assert self.result["records"][1]["map"] == 95


class TestMarkerBlocks:
    """Marker blocks should be parsed and included in the records list."""

    def setup_method(self):
        self.result: ParseResult = parse(_build_mlg_v2_marker("launch"))

    def test_marker_record_count(self):
        assert len(self.result["records"]) == 1

    def test_marker_block_type(self):
        assert self.result["records"][0]["block_type"] == "marker"

    def test_marker_message(self):
        assert self.result["records"][0]["message"] == "launch"


class TestParseV1:
    """Version-1 files use a 2-byte info_data_start and 55-byte field records."""

    def setup_method(self):
        self.result: ParseResult = parse(
            _build_mlg_v1(
                fields=[("tps", "pct", 0, 0.5, 0.0, 1)],
                data_blocks=[[512], [1024]],
            )
        )

    def test_format_version(self):
        assert self.result["format_version"] == 1

    def test_file_format(self):
        assert self.result["file_format"] == "MLVLG"

    def test_field_count(self):
        assert len(self.result["fields"]) == 1

    def test_field_name(self):
        assert self.result["fields"][0]["name"] == "tps"

    def test_field_scale(self):
        assert abs(self.result["fields"][0]["scale"] - 0.5) < 1e-5  # type: ignore[typeddict-item]

    def test_record_count(self):
        assert len(self.result["records"]) == 2

    def test_first_record_value(self):
        assert self.result["records"][0]["tps"] == 512

    def test_second_record_value(self):
        assert self.result["records"][1]["tps"] == 1024

    def test_v1_category_empty(self):
        # v1 fields have no category field; parser returns empty string
        assert self.result["fields"][0]["category"] == ""  # type: ignore[typeddict-item]


class TestFormatErrors:
    """Invalid data should raise FormatError."""

    def test_bad_magic(self):
        data = b"NOTOK\x00" + b"\x00" * 50
        with pytest.raises(FormatError, match="format"):
            parse(data)

    def test_unsupported_version(self):
        # Build a valid magic with an unsupported version number
        bad = b"MLVLG\x00" + struct.pack(">h", 99) + b"\x00" * 50
        with pytest.raises(FormatError, match="version"):
            parse(bad)


class TestModuleExports:
    """Public API should be importable from the top-level package."""

    def test_parse_callable(self):
        assert callable(ts_logs.parse)

    def test_format_error_importable(self):
        assert issubclass(ts_logs.FormatError, Exception)

    def test_parse_result_importable(self):
        from ts_logs.types import ParseResult  # noqa: F401
