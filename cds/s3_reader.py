"""
S3 객체 읽기 (IAM Roles Anywhere / credential_process 프로필용 boto3 세션).

환경 변수:
    CDS_AWS_PROFILE : ~/.aws/config 의 프로필명 (기본: my-cds-profile)
    CDS_S3_BUCKET   : 알 수 없는 등급·폴백용 단일 버킷 (기본: n2sf-c)
    CDS_S3_BUCKET_C / CDS_S3_BUCKET_S / CDS_S3_BUCKET_O : 등급별 버킷 (미설정 시 각각 n2sf-c, n2sf-s, n2sf-o)
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

import boto3

__all__ = [
    "read_s3_object_text",
    "read_s3_object_bytes",
    "get_configured_bucket",
    "get_bucket_for_doc_level",
    "tier_bucket_names",
    "doc_level_for_bucket",
    "list_objects_in_bucket",
    "read_s3_object_text_default_bucket",
]


def _profile() -> str:
    return os.environ.get("CDS_AWS_PROFILE", "my-cds-profile")


def get_configured_bucket() -> str:
    return os.environ.get("CDS_S3_BUCKET", "n2sf-c")


_DEFAULT_BUCKETS_BY_LEVEL: dict[str, str] = {
    "C": "n2sf-c",
    "S": "n2sf-s",
    "O": "n2sf-o",
}


def get_bucket_for_doc_level(doc_level: str) -> str:
    """
    문서 등급(C/S/O)에 맞는 버킷 이름을 반환한다.
    환경 변수 CDS_S3_BUCKET_C / _S / _O가 있으면 우선하고,
    없으면 기본값 n2sf-c / n2sf-s / n2sf-o를 쓴다.
    C/S/O가 아니면 CDS_S3_BUCKET(기본 n2sf-c)로 폴백한다.
    """
    lv = (doc_level or "").strip().upper()
    env_for_level = {"C": "CDS_S3_BUCKET_C", "S": "CDS_S3_BUCKET_S", "O": "CDS_S3_BUCKET_O"}
    name = env_for_level.get(lv)
    if name:
        specific = os.environ.get(name, "").strip()
        if specific:
            return specific
        return _DEFAULT_BUCKETS_BY_LEVEL[lv]
    return get_configured_bucket()


def tier_bucket_names() -> set[str]:
    """등급별로 설정된 C/S/O 버킷 이름 집합 (직접 객체 참조 시 허용 목록에 사용)."""
    return {get_bucket_for_doc_level(lv) for lv in ("C", "S", "O")}


def doc_level_for_bucket(bucket: str) -> str:
    """버킷 이름이 C/S/O 중 어디에 해당하는지 판별한다. 알 수 없으면 O로 본다."""
    b = (bucket or "").strip()
    for lv in ("C", "S", "O"):
        if get_bucket_for_doc_level(lv) == b:
            return lv
    return "O"


def list_objects_in_bucket(bucket: str, max_keys: int = 1000) -> list[dict[str, Any]]:
    """
    버킷 내 객체 메타데이터 목록 (폴더 placeholder 키는 제외).
    각 원소: Key, LastModified(datetime), Size
    """
    session = boto3.Session(profile_name=_profile())
    s3 = session.client("s3")
    out: list[dict[str, Any]] = []
    token: str | None = None
    while len(out) < max_keys:
        page_size = min(1000, max_keys - len(out))
        kwargs: dict[str, Any] = {"Bucket": bucket, "MaxKeys": page_size}
        if token:
            kwargs["ContinuationToken"] = token
        r = s3.list_objects_v2(**kwargs)
        for obj in r.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"):
                continue
            lm = obj.get("LastModified")
            if not isinstance(lm, datetime):
                lm = None
            out.append({"Key": key, "LastModified": lm, "Size": int(obj.get("Size") or 0)})
            if len(out) >= max_keys:
                break
        if not r.get("IsTruncated") or len(out) >= max_keys:
            break
        token = r.get("NextContinuationToken")
        if not token:
            break
    return out


def read_s3_object_bytes(bucket: str, key: str) -> bytes:
    session = boto3.Session(profile_name=_profile())
    s3 = session.client("s3")
    response = s3.get_object(Bucket=bucket, Key=key)
    return response["Body"].read()


def read_s3_object_text(bucket: str, key: str) -> str:
    return read_s3_object_bytes(bucket, key).decode("utf-8")


def read_s3_object_text_default_bucket(key: str) -> str:
    return read_s3_object_text(get_configured_bucket(), key)
