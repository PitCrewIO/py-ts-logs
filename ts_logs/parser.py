"""Parser for TunerStudio MLG binary log files (format version 1 and 2).

Reference specification:
  https://www.efianalytics.com/TunerStudio/docs/MLG_Binary_LogFormat_2.0.pdf
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Union

from .types import (
    BlockType,
    DisplayStyle,
    LoggerField,
    LoggerFieldBit,
    LoggerFieldScalar,
    ParseResult,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# MAGIC constant is validated against the decoded string after reading
FILE_MAGIC = "MLVLG"
SUPPORTED_VERSIONS = (1, 2)

FORMAT_LENGTH = 6
FIELD_NAME_LENGTH = 34
FIELD_UNITS_LENGTH = 10
FIELD_CATEGORY_LENGTH = 34  # v2 only
FIELD_UNUSED_LENGTH = 3
MARKER_MESSAGE_LENGTH = 50

# logger field struct sizes:
#   v1: type(1) + name(34) + units(10) + display_style(1) + scale(4) +
#       transform(4) + digits(1) = 55 bytes  (scalar)
#       type(1) + name(34) + units(10) + display_style(1) + bit_style(1) +
#       names_idx(4) + bits(1) + unused(3) = 55 bytes  (bitfield)
# v2 adds category(34) → 89 bytes per field
LOGGER_FIELD_LENGTH_V1 = 55
LOGGER_FIELD_LENGTH_V2 = 89

# ---------------------------------------------------------------------------
# Display-style & block-type lookup tables
# ---------------------------------------------------------------------------

_DISPLAY_STYLES: Dict[int, DisplayStyle] = {
    0: "Float",
    1: "Hex",
    2: "bits",
    3: "Date",
    4: "On/Off",
    5: "Yes/No",
    6: "High/Low",
    7: "Active/Inactive",
    8: "True/False",
}

_BLOCK_TYPES: Dict[int, BlockType] = {
    0: "field",
    1: "marker",
}

# Maps LoggerFieldType code → (struct format char, byte size)
_FIELD_FORMATS: Dict[int, Tuple[str, int]] = {
    0: ("B", 1),   # U08
    1: ("b", 1),   # S08
    2: ("H", 2),   # U16
    3: ("h", 2),   # S16
    4: ("I", 4),   # U32
    5: ("i", 4),   # S32
    6: ("q", 8),   # S64
    7: ("f", 4),   # F32
    10: ("B", 1),  # U08_BITFIELD
    11: ("H", 2),  # U16_BITFIELD
    12: ("I", 4),  # U32_BITFIELD
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def parse(source: Union[bytes, str, Path]) -> ParseResult:
    """Parse a TunerStudio MLG binary log.

    Parameters
    ----------
    source:
        Either the raw binary data (``bytes``) **or** a file path
        (``str`` / :class:`pathlib.Path`) that will be opened and read.

    Returns
    -------
    :class:`~ts_logs.types.ParseResult`
        A :class:`typing.TypedDict` containing the parsed header metadata,
        field definitions, and all data records.
    """
    if isinstance(source, (str, Path)):
        data = Path(source).read_bytes()
    elif isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    else:
        raise TypeError(
            "source must be bytes, str, or pathlib.Path, "
            f"got {type(source).__name__!r}"
        )

    return _Parser(data).parse()


# ---------------------------------------------------------------------------
# Internal parser
# ---------------------------------------------------------------------------

class FormatError(ValueError):
    """Raised when the file does not match the expected MLG format."""


class _Parser:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0
        self._length = len(data)

    # ------------------------------------------------------------------
    # Low-level reading helpers
    # ------------------------------------------------------------------

    def _read_bytes(self, n: int) -> bytes:
        end = self._offset + n
        if end > self._length:
            raise FormatError(
                f"Truncated data at offset {self._offset}: needed {n} bytes, "
                f"have {self._length - self._offset}"
            )
        chunk = self._data[self._offset : end]
        self._offset = end
        return chunk

    def _unpack(self, fmt: str) -> tuple:
        """Read and unpack a big-endian struct format string."""
        size = struct.calcsize(fmt)
        try:
            values = struct.unpack_from(">" + fmt, self._data, self._offset)
        except struct.error as exc:
            raise FormatError(
                f"Truncated data at offset {self._offset}: {exc}"
            ) from exc
        self._offset += size
        return values

    def _read_u8(self) -> int:
        (v,) = self._unpack("B")
        return v

    def _read_i16(self) -> int:
        (v,) = self._unpack("h")
        return v

    def _read_u16(self) -> int:
        (v,) = self._unpack("H")
        return v

    def _read_i32(self) -> int:
        (v,) = self._unpack("i")
        return v

    def _read_u32(self) -> int:
        (v,) = self._unpack("I")
        return v

    def _read_f32(self) -> float:
        (v,) = self._unpack("f")
        return v

    def _read_string(self, length: int) -> str:
        raw = self._read_bytes(length)
        return raw.decode("latin-1").replace("\x00", "").strip().strip('"')

    def _jump(self, offset: int) -> None:
        self._offset = offset

    # ------------------------------------------------------------------
    # Top-level parse
    # ------------------------------------------------------------------

    def parse(self) -> ParseResult:
        (
            file_format,
            format_version,
            timestamp,
            info_data_start,
            data_begin_index,
            record_length,
            num_logger_fields,
        ) = self._parse_header()

        is_v2 = format_version == 2
        logger_field_length = LOGGER_FIELD_LENGTH_V2 if is_v2 else LOGGER_FIELD_LENGTH_V1

        fields, bitfield_names_raw = self._parse_logger_fields(
            num_logger_fields, logger_field_length, info_data_start, is_v2
        )

        # info data sits between bitfield names section and data begin index;
        # subtract 1 for the NUL sentinel byte that terminates the info section
        self._jump(info_data_start)
        info_section_length = data_begin_index - 1 - info_data_start
        info_data = self._read_string(max(info_section_length, 0))

        self._jump(data_begin_index)
        records = self._parse_data_blocks(fields)

        return ParseResult(
            file_format=file_format,
            format_version=format_version,
            timestamp=timestamp,
            info=info_data,
            bit_field_names=bitfield_names_raw,
            fields=fields,
            record_length=record_length,
            records=records,
        )

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    def _parse_header(
        self,
    ) -> Tuple[str, int, datetime, int, int, int, int]:
        # File format: 6 bytes
        file_format = self._read_string(FORMAT_LENGTH)

        if file_format != FILE_MAGIC:
            raise FormatError(
                f"Unsupported file format: {file_format!r}. "
                "Expected 'MLVLG'."
            )

        format_version = self._read_i16()
        if format_version not in SUPPORTED_VERSIONS:
            raise FormatError(
                f"Unsupported format version: {format_version}. "
                f"Supported: {SUPPORTED_VERSIONS}."
            )

        is_v2 = format_version == 2

        # Unix timestamp (4 bytes, may be 0)
        ts_raw = self._read_i32()
        timestamp = (
            datetime.fromtimestamp(ts_raw, tz=timezone.utc)
            if ts_raw
            else datetime(1970, 1, 1, tzinfo=timezone.utc)
        )

        # Info data start: 4 bytes in v2, 2 bytes in v1
        info_data_start = self._read_i32() if is_v2 else self._read_u16()

        data_begin_index = self._read_i32()
        record_length = self._read_u16()
        num_logger_fields = self._read_u16()

        return (
            file_format,
            format_version,
            timestamp,
            info_data_start,
            data_begin_index,
            record_length,
            num_logger_fields,
        )

    # ------------------------------------------------------------------
    # Logger field definitions
    # ------------------------------------------------------------------

    def _parse_logger_fields(
        self,
        num_fields: int,
        field_length: int,
        info_data_start: int,
        is_v2: bool,
    ) -> Tuple[Dict[str, LoggerField], str]:
        fields: Dict[str, LoggerField] = {}
        fields_end = self._offset + num_fields * field_length

        while self._offset < fields_end:
            ftype = self._read_u8()
            name = self._read_string(FIELD_NAME_LENGTH)
            units = self._read_string(FIELD_UNITS_LENGTH)
            display_style = _DISPLAY_STYLES.get(self._read_u8(), "Float")

            if ftype < 10:
                # scalar field
                scale = self._read_f32()
                transform = self._read_f32()
                digits = self._read_u8()
                category = self._read_string(FIELD_CATEGORY_LENGTH) if is_v2 else ""
                fields[name] = LoggerFieldScalar(
                        type=ftype,
                        units=units,
                        display_style=display_style,  # type: ignore[arg-type]
                        scale=scale,
                        transform=transform,
                        digits=digits,
                        category=category,
                    )
            else:
                # bit field
                bit_field_style = _DISPLAY_STYLES.get(self._read_u8(), "Float")
                bit_field_names_index = self._read_i32()
                bits = self._read_u8()
                _unused = self._read_bytes(FIELD_UNUSED_LENGTH)
                category = self._read_string(FIELD_CATEGORY_LENGTH) if is_v2 else ""
                fields[name] = LoggerFieldBit(
                        type=ftype,
                        units=units,
                        display_style=display_style,  # type: ignore[arg-type]
                        bit_field_style=bit_field_style,  # type: ignore[arg-type]
                        bit_field_names_index=bit_field_names_index,
                        bits=bits,
                        category=category,
                    )

        # bit-field names string between field definitions and info data start
        bitfield_names_length = info_data_start - fields_end
        bitfield_names_raw = self._read_string(max(bitfield_names_length, 0))

        return fields, bitfield_names_raw

    # ------------------------------------------------------------------
    # Data blocks
    # ------------------------------------------------------------------

    def _parse_data_blocks(
        self, fields: Dict[str, LoggerField]
    ) -> List[Dict[str, Union[int, float, str]]]:
        records: List[Dict[str, Union[int, float, str]]] = []

        while self._offset < self._length:
            # Each block header is 4 bytes (type, counter, timestamp×2).
            # Guard against truncated trailing data that can't form a full header.
            if self._offset + 4 > self._length:
                break
            block_type_code = self._read_u8()
            # skip counter byte
            self._offset += 1
            timestamp = self._read_u16()

            block_type = _BLOCK_TYPES.get(block_type_code)
            if block_type is None:
                raise FormatError(
                    f"Unsupported block type code: {block_type_code} "
                    f"at offset {self._offset - 4}."
                )

            record: Dict[str, Union[int, float, str]] = {
                "block_type": block_type,
                "relative_timestamp": timestamp,
            }

            if block_type_code == 0:
                # field data block
                for field_name, field in fields.items():
                    field_fmt = _FIELD_FORMATS.get(field["type"])
                    if field_fmt is None:
                        raise FormatError(
                            f"Unknown field type code {field['type']!r} "
                            f"for field {field_name!r}."
                        )
                    fmt_char, byte_size = field_fmt
                    try:
                        (value,) = struct.unpack_from(
                            ">" + fmt_char, self._data, self._offset
                        )
                    except struct.error as exc:
                        raise FormatError(
                            f"Truncated data reading field {field_name!r} "
                            f"at offset {self._offset}: {exc}"
                        ) from exc
                    self._offset += byte_size
                    record[field_name] = value

                # skip CRC byte
                self._offset += 1

            elif block_type_code == 1:
                # marker block
                record["message"] = self._read_string(MARKER_MESSAGE_LENGTH)

            records.append(record)

        return records
