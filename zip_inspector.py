"""Bounded, offline ZIP metadata and selected-text inspection; no extraction."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import ntpath
import os
from pathlib import Path
import re
import stat
import struct
import unicodedata
import zipfile
import zlib


LIMITS = {
    "archive_bytes": 8 * 1024 * 1024,
    "central_directory_bytes": 128 * 1024,
    "entries": 128,
    "member_bytes": 2 * 1024 * 1024,
    "total_member_bytes": 8 * 1024 * 1024,
    "expansion_ratio": 100,
    "path_bytes": 512,
    "text_files": 8,
    "text_bytes_each": 64 * 1024,
    "text_bytes_total": 256 * 1024,
    "findings": 64,
    "evidence_chars": 240,
}
TEXT_NAMES = {"readme", "agents", "instructions", "contributing", "security"}
TEXT_SUFFIXES = {"", ".md", ".txt", ".rst"}
NESTED_SUFFIXES = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"}
# These fixed patterns classify *suspected* instructions, including quotations.
# Input never supplies patterns, tools, callbacks, commands or authority.
RULES = tuple((name, re.compile(pattern, re.IGNORECASE | re.MULTILINE)) for name, pattern in (
    ("INSTRUCTION_OVERRIDE", r"\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above|system|developer)\s+(?:instructions?|prompts?|rules?)\b|(?:先行|以前|前の|上位|システム|開発者)(?:の)?(?:指示|命令|ルール)[^\n]{0,24}(?:無視|上書き)"),
    ("ROLE_SPOOFING", r"^[ \t]*(?:\[(?:system|developer)\]|<\|im_start\|>(?:system|developer)|(?:system|developer)[ \t]*:)|(?:AI|アシスタント|解析者|レビュアー)(?:への|向けの|の)(?:新しい|最優先の)?指示"),
    ("AUTHORITY_SPOOFING", r"\b(?:approval|authority|permission)\s+(?:is\s+)?(?:granted|approved)\b|\bowner\s+(?:has\s+)?(?:already\s+)?approved\b|(?:承認|許可)(?:は|が)?(?:取得済み|承認済み|付与済み)"),
    ("PRIVILEGE_REQUEST", r"\b(?:grant|enable|request|obtain)\b[^\n]{0,70}\b(?:admin(?:istrator)?|root|elevated|permissions?|privileges?)\b|\bsudo\b|(?:管理者|root|追加)(?:の)?権限[^\n]{0,30}(?:付与|取得|要求|許可)"),
    ("DATA_TRANSMISSION_REQUEST", r"\b(?:send|upload|transmit|email|post)\b[^\n]{0,120}(?:https?://|\b(?:secrets?|api[ _-]?keys?|tokens?|credentials?|private[ _-]?files?|environment[ _-]?variables?)\b)|(?:秘密|認証情報|APIキー|トークン|環境変数)[^\n]{0,80}(?:送信|アップロード|外部へ)"),
    ("TOOL_EXECUTION_REQUEST", r"\b(?:run|execute|invoke|call)\s+(?:the\s+)?(?:shell|terminal|command|tool|curl|bash|python|browser)\b|(?:シェル|コマンド|ツール)[^\n]{0,30}(?:実行|呼び出し)"),
    ("FINDING_SUPPRESSION", r"\b(?:hide|suppress|omit|conceal)\b[^\n]{0,70}\b(?:findings?|warnings?|injection|prompt_manipulation)\b|(?:所見|警告|検出結果)[^\n]{0,30}(?:隠|抑制|報告しない)"),
))


def _unknown(report, code, entry=None):
    item = {"code": code}
    if entry is not None:
        item["entry_index"] = entry["index"]
        entry["issues"].append(code)
    report["unknown_conditions"].append(item)


def _finish(report):
    unknown = bool(report["unknown_conditions"])
    report["inspection_status"] = "UNKNOWN" if unknown else "COMPLETE"
    report["prompt_injection"] = (
        "DETECTED" if report["findings"] else
        "UNINSPECTABLE" if unknown or not report["coverage"]["text_files_read"] else
        "NOT_DETECTED"
    )
    report["gate"] = "HOLD" if unknown or report["findings"] else "CAP"
    return report


def _directory_bound(data):
    """Bound actual CD records *before* ZipFile allocates ZipInfo objects.

    ZipFile remains the ZIP parser. This preflight supports ordinary, single-disk
    ZIPs only; ZIP64, split/SFX/trailing containers return UNKNOWN.
    """
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        raise ValueError("MALFORMED_ZIP_END")
    _, disk, cd_disk, disk_count, count, size, offset, comment = struct.unpack_from("<4s4H2LH", data, end)
    if 65535 in (disk_count, count) or 0xFFFFFFFF in (size, offset):
        raise ValueError("ZIP64_UNSUPPORTED")
    if disk or cd_disk or disk_count != count:
        raise ValueError("MULTI_DISK_UNSUPPORTED")
    if count > LIMITS["entries"]:
        raise ValueError("ENTRY_COUNT_LIMIT")
    if size > LIMITS["central_directory_bytes"]:
        raise ValueError("CENTRAL_DIRECTORY_SIZE_LIMIT")
    if (end + 22 + comment != len(data) or offset + size != end
            or (count and not data.startswith(b"PK\x03\x04"))):
        raise ValueError("CONTAINER_LAYOUT_UNSUPPORTED")
    pos, actual = offset, 0
    while pos < end:
        if pos + 46 > end or data[pos:pos + 4] != b"PK\x01\x02":
            raise ValueError("MALFORMED_CENTRAL_DIRECTORY")
        lengths = struct.unpack_from("<3H", data, pos + 28)
        pos += 46 + sum(lengths)
        actual += 1
        if actual > LIMITS["entries"]:
            raise ValueError("ENTRY_COUNT_LIMIT")
    if pos != end or actual != count:
        raise ValueError("CENTRAL_DIRECTORY_COUNT_MISMATCH")
    return offset


def _selected(name):
    path = Path(name)
    return path.stem.casefold() in TEXT_NAMES and path.suffix.casefold() in TEXT_SUFFIXES


def _scan(report, entry, text):
    for category, pattern in RULES:
        for match in pattern.finditer(text):
            if len(report["findings"]) >= LIMITS["findings"]:
                _unknown(report, "FINDING_LIMIT", entry)
                return
            report["findings"].append({
                "category": category,
                "entry_index": entry["index"],
                "path": entry["path"],
                "line": text.count("\n", 0, match.start()) + 1,
                "start_char": match.start(),
                "end_char": match.end(),
                "matched_text": match.group()[:LIMITS["evidence_chars"]],
                "source_role": "UNTRUSTED_ARCHIVE_DATA",
            })


def inspect_zip(path: str | os.PathLike) -> dict:
    """Read one regular ZIP snapshot; return finite JSON-compatible evidence.

    Only the named input is opened, read-only. No member is written to disk,
    imported, executed, recursively inspected or sent anywhere. Bounded selected
    text is decompressed in memory, which is necessary to inspect compressed text.
    """
    report = {
        "format": "orchard-c-static-zip/1.0",
        "limits": dict(LIMITS),
        "input": {}, "entries": [], "findings": [], "unknown_conditions": [],
        "coverage": {"listed_entries": 0, "text_files_read": 0, "text_bytes_read": 0},
        "safety_proven": False,
        "authorizes_actions": False,
        "scope": "Metadata and allowlisted UTF-8 text only; CAP permits this static report only.",
        "limitations": [
            "NOT_DETECTED is not proof of safety or absence of prompt injection.",
            "Fixed English/Japanese heuristics can miss obfuscation and other languages and can flag quotations.",
            "Nonselected content, nested archives and binary payloads are not content-scanned; their CRC is not verified.",
            "No malware, execution, OS isolation, VM or AI-model resistance claim.",
        ],
    }
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                _unknown(report, "INPUT_NOT_REGULAR_FILE")
                return _finish(report)
            if before.st_size > LIMITS["archive_bytes"]:
                _unknown(report, "ARCHIVE_SIZE_LIMIT")
                return _finish(report)
            data = source.read(LIMITS["archive_bytes"] + 1)
            after = os.fstat(source.fileno())
        report["input"] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if len(data) > LIMITS["archive_bytes"]:
            _unknown(report, "ARCHIVE_SIZE_LIMIT")
            return _finish(report)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            _unknown(report, "INPUT_CHANGED_DURING_READ")
            return _finish(report)
    except (OSError, ValueError) as exc:
        _unknown(report, "INPUT_UNREADABLE_" + type(exc).__name__)
        return _finish(report)

    try:
        directory_start = _directory_bound(data)
    except ValueError as exc:
        _unknown(report, str(exc))
        return _finish(report)
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            total = sum(info.file_size for info in infos)
            report["coverage"]["declared_total_member_bytes"] = total
            if total > LIMITS["total_member_bytes"]:
                _unknown(report, "TOTAL_MEMBER_SIZE_LIMIT")
            seen = set()
            for index, info in enumerate(infos):
                name = info.orig_filename
                entry = {
                    "index": index, "path": name[:LIMITS["path_bytes"]],
                    "compressed_bytes": info.compress_size, "uncompressed_bytes": info.file_size,
                    "expansion_ratio": round(info.file_size / max(1, info.compress_size), 3),
                    "compression_method": info.compress_type, "encrypted": bool(info.flag_bits & 1),
                    "directory": info.is_dir(), "issues": [], "text_status": "NOT_SELECTED",
                }
                report["entries"].append(entry)
                if len(name.encode("utf-8")) > LIMITS["path_bytes"]:
                    _unknown(report, "PATH_SIZE_LIMIT", entry)
                parts = name.rstrip("/").split("/")
                if (not name or name.startswith("/") or ntpath.splitdrive(name)[0] or "\\" in name
                        or any(part in {"", ".", ".."} for part in parts)
                        or any(unicodedata.category(c).startswith("C") for c in name)):
                    _unknown(report, "UNSAFE_OR_AMBIGUOUS_PATH", entry)
                identity = unicodedata.normalize("NFC", name.rstrip("/")).casefold()
                if identity in seen:
                    _unknown(report, "DUPLICATE_OR_COLLIDING_PATH", entry)
                seen.add(identity)
                kind = stat.S_IFMT(info.external_attr >> 16)
                if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    _unknown(report, "LINK_OR_SPECIAL_FILE_UNSUPPORTED", entry)
                if info.flag_bits & 1:
                    _unknown(report, "ENCRYPTED_ENTRY_UNSUPPORTED", entry)
                if info.flag_bits & ~0x080E:
                    _unknown(report, "ZIP_FLAGS_UNSUPPORTED", entry)
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    _unknown(report, "COMPRESSION_UNSUPPORTED", entry)
                if info.extract_version > 20 or info.volume:
                    _unknown(report, "ZIP_VERSION_OR_VOLUME_UNSUPPORTED", entry)
                if info.file_size > LIMITS["member_bytes"]:
                    _unknown(report, "MEMBER_SIZE_LIMIT", entry)
                if info.file_size > LIMITS["expansion_ratio"] * max(1, info.compress_size):
                    _unknown(report, "EXPANSION_RATIO_LIMIT", entry)
                pos = info.header_offset
                if not (0 <= pos and pos + 30 <= directory_start):
                    _unknown(report, "LOCAL_HEADER_OFFSET_INVALID", entry)
                elif data[pos:pos + 4] != b"PK\x03\x04":
                    _unknown(report, "LOCAL_HEADER_INVALID", entry)
                else:
                    header = struct.unpack_from("<4s5H3L2H", data, pos)
                    start = pos + 30 + header[-2] + header[-1]
                    if header[2:4] != (info.flag_bits, info.compress_type):
                        _unknown(report, "LOCAL_METADATA_MISMATCH", entry)
                    if not info.flag_bits & 8 and header[6:9] != (info.CRC, info.compress_size, info.file_size):
                        _unknown(report, "LOCAL_METADATA_MISMATCH", entry)
                    if start + info.compress_size > directory_start:
                        _unknown(report, "MEMBER_SPAN_INVALID", entry)
                    # ZipFile validates local names and overlapping entry spans
                    # without decompressing nonselected payloads.
                    if not entry["issues"]:
                        try:
                            with archive.open(info, "r"):
                                pass
                        except (OSError, EOFError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
                            _unknown(report, "LOCAL_HEADER_UNREADABLE_" + type(exc).__name__, entry)
                if info.compress_type == zipfile.ZIP_STORED and info.compress_size != info.file_size:
                    _unknown(report, "STORED_SIZE_MISMATCH", entry)
                if Path(name).suffix.casefold() in NESTED_SUFFIXES:
                    _unknown(report, "NESTED_ARCHIVE_UNINSPECTED", entry)
            report["coverage"]["listed_entries"] = len(infos)
            selected = 0
            text_budget_used = 0
            for info, entry in zip(infos, report["entries"]):
                if info.is_dir() or not _selected(info.orig_filename):
                    continue
                selected += 1
                entry["text_status"] = "UNINSPECTABLE"
                if entry["issues"] or total > LIMITS["total_member_bytes"]:
                    continue
                if selected > LIMITS["text_files"]:
                    _unknown(report, "TEXT_FILE_COUNT_LIMIT", entry)
                    continue
                remaining = LIMITS["text_bytes_total"] - text_budget_used
                cap = min(LIMITS["text_bytes_each"], remaining)
                if info.file_size > cap:
                    _unknown(report, "TEXT_BYTE_LIMIT", entry)
                    continue
                # Reserve the whole possible read before parsing. Failed or
                # forged streams consume this reservation, never a fresh budget.
                text_budget_used += cap
                try:
                    with archive.open(info, "r") as member:
                        raw = member.read(cap + 1)
                    report["coverage"]["text_bytes_read"] += len(raw)
                    if info.compress_type == zipfile.ZIP_DEFLATED:
                        # ZipExtFile clips at the *declared* uncompressed size.
                        # Check the bounded actual stream too, so a forged small
                        # size/CRC cannot hide text after an innocent prefix.
                        pos = info.header_offset
                        name_len, extra_len = struct.unpack_from("<2H", data, pos + 26)
                        start = pos + 30 + name_len + extra_len
                        decoder = zlib.decompressobj(-15)
                        actual = decoder.decompress(data[start:start + info.compress_size], cap + 1)
                        if (len(actual) > cap or len(actual) != info.file_size or not decoder.eof
                                or decoder.unused_data or decoder.unconsumed_tail or actual != raw):
                            _unknown(report, "ACTUAL_TEXT_STREAM_MISMATCH_OR_LIMIT", entry)
                            continue
                    if len(raw) > cap or len(raw) != info.file_size:
                        _unknown(report, "TEXT_LENGTH_MISMATCH", entry)
                        continue
                    text_budget_used -= cap - len(raw)
                    text = raw.decode("utf-8")
                except (OSError, EOFError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile, UnicodeError, zlib.error) as exc:
                    _unknown(report, "TEXT_UNREADABLE_" + type(exc).__name__, entry)
                    continue
                if any(unicodedata.category(c).startswith("C") and c not in "\n\r\t" for c in text):
                    _unknown(report, "TEXT_CONTROL_OR_FORMAT_CHARACTER", entry)
                entry["text_status"] = "READ_UTF8"
                entry["text_sha256"] = hashlib.sha256(raw).hexdigest()
                report["coverage"]["text_files_read"] += 1
                _scan(report, entry, text)
            if not selected:
                _unknown(report, "NO_ALLOWLISTED_TEXT")
    except (OSError, EOFError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile, UnicodeError, zlib.error) as exc:
        _unknown(report, "ZIP_UNREADABLE_" + type(exc).__name__)
    return _finish(report)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_path", help="One local ZIP; this MVP is validated with synthetic inputs only")
    args = parser.parse_args(argv)
    report = inspect_zip(args.zip_path)
    # ASCII JSON escapes untrusted control characters and bidi in terminal output.
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 2 if report["inspection_status"] == "UNKNOWN" else 0


if __name__ == "__main__":
    raise SystemExit(main())
