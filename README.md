# py-ts-logs

Python library for parsing EFI Analytics TunerStudio MLG binary log files for
Megasquirt.

## Installation

```bash
pip install py-ts-logs
```

## Usage

```python
import ts_logs

# From a file path
result = ts_logs.parse("path/to/log.mlg")

# From raw bytes
with open("path/to/log.mlg", "rb") as f:
    data = f.read()
result = ts_logs.parse(data)
```

### Return value

`parse()` returns a `ParseResult` `TypedDict` with the following keys:

| Key               | Type                        | Description                                      |
|-------------------|-----------------------------|--------------------------------------------------|
| `file_format`     | `str`                       | Magic string – always `"MLVLG"`                  |
| `format_version`  | `int`                       | Format version (`1` or `2`)                      |
| `timestamp`       | `datetime`                  | UTC timestamp embedded in the log header          |
| `info`            | `str`                       | Free-text info section (may be empty)            |
| `bit_field_names` | `str`                       | Packed bit-field name strings                    |
| `fields`          | `List[LoggerField]`         | Channel/field definitions from the file header   |
| `records`         | `List[Dict[str, ...]]`      | Parsed data records; each dict contains the channel name as key and raw integer/float value as value, plus `block_type` and `timestamp` |

`LoggerField` is a union of `LoggerFieldScalar` and `LoggerFieldBit`, both of
which are `TypedDict`s.

## Format

The file format parsed is the **MLVLG (MegaLogViewer Log) binary format**,
versions 1 and 2, as documented in the [EFI Analytics specification][spec].

All fields in the binary file are encoded in **big-endian** byte order.

[spec]: https://www.efianalytics.com/TunerStudio/docs/MLG_Binary_LogFormat_2.0.pdf

## Development

```bash
pip install -e ".[dev]"
pytest
```
