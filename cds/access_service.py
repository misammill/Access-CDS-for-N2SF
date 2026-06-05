"""
access_service.py
=================
문서 조회 요청 처리 및 등급 기반 접근 제어 서비스 (PoC/데모용)

정책 요약 (조회):
    - user 등급 >= doc 등급 → 원문 반환
    - user 등급 <  doc 등급 → 민감정보 마스킹 후 반환 (403 차단 없음)

처리 흐름:
    1. doc_id 로 문서 조회 (s3r1.* 참조 또는 PoC 인메모리 샘플)
    2. filter_engine.mask_text() 로 등급에 따라 원문/마스킹본 반환
"""

from __future__ import annotations

from typing import Any

import filter_engine
from s3_inventory import REF_PREFIX, fetch_document_from_s3_ref

# Swagger·로컬 API 테스트용 인메모리 샘플 (S3 없이 C-001 등 조회 가능)
_DOCUMENT_STORE: dict[str, dict[str, str]] = {
    "C-001": {
        "doc_id": "C-001",
        "title": "비공개 정책 대응 문서",
        "doc_level": "C",
        "content": (
            "본 문서는 내부 보안사고 대응 절차를 기술한 기밀 문서입니다. "
            "담당자 홍길동(010-9876-5432)이 총괄하며, 주민등록번호 820315-1234567을 "
            "포함한 인원 정보는 외부 유출이 엄격히 금지됩니다. "
            "사건번호 C-2026-001, 계좌 122-456-789012로의 예산 집행 내역도 포함됩니다."
        ),
    },
    "S-001": {
        "doc_id": "S-001",
        "title": "인사 평가 문서",
        "doc_level": "S",
        "content": (
            "직원 박지훈의 주민등록번호는 990101-1234567이고 "
            "이메일은 pjh@company.com이며, 2026년 1분기 인사평가 점수는 89점입니다. "
            "연락처: 010-2345-6789, 소속 부서: 정보보안팀."
        ),
    },
    "O-001": {
        "doc_id": "O-001",
        "title": "공개 교육 일정 안내",
        "doc_level": "O",
        "content": (
            "2026년 상반기 정보보안 교육은 5월 20일(화) 오후 2시에 "
            "본관 3층 대회의실에서 진행됩니다. "
            "문의: edu@example.org / 02-1234-5678"
        ),
    },
}


def get_document(doc_id: str) -> dict[str, Any] | None:
    """
    doc_id 로 문서를 조회한다.

    - `s3r1.*` : S3 버킷 객체 참조 (/documents/s3-index 가 발급)
    - `C-001` 등 : PoC 인메모리 샘플
    """
    key = str(doc_id).strip()
    cached = _DOCUMENT_STORE.get(key)
    if cached is not None:
        return cached

    if key.startswith(REF_PREFIX):
        return fetch_document_from_s3_ref(key)

    return None


def access_document(
    doc_id: str,
    user_level: str,
    mask_open_docs: bool = False,
) -> dict[str, Any]:
    """
    사용자의 문서 조회 요청을 처리한다.

    filter_engine.mask_text()로 등급(user vs doc)에 따라 원문 또는 마스킹본을 반환한다.
    """
    user_level = user_level.upper()

    doc = get_document(doc_id)
    if doc is None:
        return {
            "success": False,
            "doc_id": doc_id,
            "title": None,
            "doc_level": None,
            "user_level": user_level,
            "allowed": False,
            "masked_text": None,
            "masked_entities": [],
            "message": "document not found",
        }

    doc_level = doc["doc_level"]
    title = doc["title"]
    content = doc["content"]
    s3_source_format = doc.get("s3_source_format")

    filter_result = filter_engine.mask_text(
        text=content,
        doc_level=doc_level,
        user_level=user_level,
        mask_open_docs=mask_open_docs,
    )

    out: dict[str, Any] = {
        "success": True,
        "doc_id": doc_id,
        "title": title,
        "doc_level": doc_level,
        "user_level": user_level,
        "allowed": filter_result["allowed"],
        "masked_text": filter_result["masked_text"],
        "masked_entities": filter_result.get("masked_entities", []),
        "message": filter_result["message"],
    }
    if s3_source_format:
        out["s3_source_format"] = s3_source_format
    return out
