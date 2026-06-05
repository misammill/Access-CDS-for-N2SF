"""
S3 등급별 버킷(n2sf-c / n2sf-s / n2sf-o) 객체 목록 통합 및 doc_id(ref) 인코딩.

웹 목록·GET /access/{doc_id} 에서 사용한다.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

from botocore.exceptions import ClientError

from s3_reader import (
    doc_level_for_bucket,
    get_bucket_for_doc_level,
    list_objects_in_bucket,
    read_s3_object_bytes,
    read_s3_object_text,
    tier_bucket_names,
)

log = logging.getLogger(__name__)

REF_PREFIX = "s3r1."


def encode_s3_object_ref(bucket: str, object_key: str) -> str:
    payload = f"{bucket.strip()}\n{object_key}"
    b = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    return REF_PREFIX + b


def decode_s3_object_ref(doc_id: str) -> tuple[str, str] | None:
    doc_id = doc_id.strip()
    if not doc_id.startswith(REF_PREFIX):
        return None
    raw = doc_id[len(REF_PREFIX) :]
    pad = "=" * (-len(raw) % 4)
    try:
        decoded = base64.urlsafe_b64decode(raw + pad).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if "\n" not in decoded:
        return None
    bucket, key = decoded.split("\n", 1)
    return bucket.strip(), key


def is_allowed_tier_bucket(bucket: str) -> bool:
    return bucket.strip() in tier_bucket_names()


def _s3_key_is_docx(key: str) -> bool:
    return key.lower().endswith(".docx")


def load_s3_ref_object_bytes(doc_id: str) -> tuple[str, str, str, str, bytes] | None:
    """
    s3r1.* 참조의 원시 바이트를 읽는다.
    반환: (bucket, s3_key, doc_level, title, raw_bytes) 또는 None.
    """
    ref = decode_s3_object_ref(doc_id)
    if ref is None:
        return None
    bucket, s3_key = ref
    if not is_allowed_tier_bucket(bucket):
        return None
    try:
        raw = read_s3_object_bytes(bucket, s3_key)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
            return None
        raise
    title = s3_key.rsplit("/", 1)[-1] or s3_key
    doc_level = doc_level_for_bucket(bucket)
    return bucket, s3_key, doc_level, title, raw


def fetch_document_from_s3_ref(doc_id: str) -> dict[str, Any] | None:
    """s3r1.* doc_id 로 허용된 등급 버킷만 읽어 문서 dict를 만든다."""
    ref = decode_s3_object_ref(doc_id)
    if ref is None:
        return None
    bucket, s3_key = ref
    if not is_allowed_tier_bucket(bucket):
        return None
    title = s3_key.rsplit("/", 1)[-1] or s3_key
    doc_level = doc_level_for_bucket(bucket)

    if _s3_key_is_docx(s3_key):
        try:
            raw = read_s3_object_bytes(bucket, s3_key)
            from docx_mask import docx_bytes_plain_text

            plain = docx_bytes_plain_text(raw)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                return None
            raise
        except Exception as e:
            log.warning("docx 본문 추출 실패 key=%s: %s", s3_key, e)
            return None
        return {
            "doc_id": doc_id,
            "title": title,
            "doc_level": doc_level,
            "content": plain,
            "s3_source_format": "docx",
        }

    try:
        content = read_s3_object_text(bucket, s3_key)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
            return None
        raise
    return {
        "doc_id": doc_id,
        "title": title,
        "doc_level": doc_level,
        "content": content,
    }


def list_combined_s3_documents(max_per_bucket: int = 500) -> list[dict[str, Any]]:
    """
    C/S/O 버킷을 순회해 객체를 한 리스트로 합친다.
    각 행: doc_id, title, doc_level, bucket, s3_key, created_at(ISO), size
    """
    rows: list[dict[str, Any]] = []
    for level in ("C", "S", "O"):
        bucket = get_bucket_for_doc_level(level)
        try:
            objs = list_objects_in_bucket(bucket, max_keys=max_per_bucket)
        except ClientError as e:
            log.warning("S3 list_objects 실패 bucket=%s: %s", bucket, e)
            continue
        for o in objs:
            key = o["Key"]
            lm = o.get("LastModified")
            created = lm.isoformat() if lm else None
            rows.append(
                {
                    "doc_id": encode_s3_object_ref(bucket, key),
                    "title": key.rsplit("/", 1)[-1] or key,
                    "doc_level": level,
                    "bucket": bucket,
                    "s3_key": key,
                    "created_at": created,
                    "size": o.get("Size", 0),
                }
            )
    rows.sort(key=lambda r: (r["doc_level"], r["title"].lower()))
    return rows
