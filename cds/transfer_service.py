"""
transfer_service.py
===================
문서를 보안 등급 영역(C / S / O) 간 전송할 때의 정책 판단 및 처리 서비스 (PoC/데모용)

전송 정책 요약:
    ┌──────────────┬──────────────┬──────────────────────────────────────┐
    │ 문서 등급    │ 목적지 등급  │ 처리                                 │
    ├──────────────┼──────────────┼──────────────────────────────────────┤
    │ C            │ C            │ 허용 (마스킹 없음)                   │
    │ C            │ S / O        │ 차단 (하향 전송 금지)                │
    │ S            │ S            │ 허용 (마스킹 없음)                   │
    │ S            │ O            │ 허용 (강제 마스킹 적용)              │
    │ S            │ C            │ 차단 (상향 전송 금지)                │
    │ O            │ O            │ 허용 (마스킹 없음)                   │
    │ O            │ S / C        │ 차단 (상향 전송 금지)                │
    └──────────────┴──────────────┴──────────────────────────────────────┘

추가 규칙:
    - 사용자 등급보다 높은 문서는 전송 요청 자체 불가
    - 모든 전송 전 본문 검사(마스킹 엔진) 수행
    - build_transfer_audit_log() 로 감사 로그 구조 생성

FastAPI 연동:
    from transfer_service import transfer_document
    result = transfer_document(doc, user_level="S", target_level="O")
"""

from __future__ import annotations

import datetime
from typing import Any

import filter_engine


# ---------------------------------------------------------------------------
# 1. 등급 상수 및 순위 매핑
# ---------------------------------------------------------------------------

class DocumentLevel:
    """문서 보안 등급 상수. C > S > O 순으로 높음."""
    C = "C"  # 기밀 (Confidential)
    S = "S"  # 민감 (Sensitive)
    O = "O"  # 공개 (Open)


class UserLevel:
    """사용자 보안 등급 상수. C > S > O 순으로 높음."""
    C = "C"
    S = "S"
    O = "O"


# 등급 → 숫자 순위 (클수록 높은 등급)
_LEVEL_RANK: dict[str, int] = {"C": 3, "S": 2, "O": 1}

# 허용된 전송 규칙 테이블
# (doc_level, target_level) -> (허용 여부, 강제 마스킹 여부)
_TRANSFER_POLICY: dict[tuple[str, str], tuple[bool, bool]] = {
    ("C", "C"): (True,  False),  # C → C : 허용, 마스킹 없음
    ("C", "S"): (False, False),  # C → S : 하향 전송 차단
    ("C", "O"): (False, False),  # C → O : 하향 전송 차단
    ("S", "C"): (False, False),  # S → C : 상향 전송 차단
    ("S", "S"): (True,  False),  # S → S : 허용, 마스킹 없음
    ("S", "O"): (True,  True),   # S → O : 허용, 강제 마스킹 필수
    ("O", "C"): (False, False),  # O → C : 상향 전송 차단
    ("O", "S"): (False, False),  # O → S : 상향 전송 차단
    ("O", "O"): (True,  False),  # O → O : 허용, 마스킹 없음
}


# ---------------------------------------------------------------------------
# 2. 전송 허용 판단 함수
# ---------------------------------------------------------------------------

def can_transfer(
    user_level: str,
    doc_level: str,
    target_level: str,
) -> tuple[bool, str]:
    """
    사용자의 전송 요청이 정책상 허용되는지 판단한다.

    판단 순서:
        1. 사용자 등급이 문서 등급보다 낮으면 즉시 차단
        2. (doc_level, target_level) 조합을 정책 테이블에서 조회
        3. 정책 테이블에 없는 조합은 기본 차단

    Args:
        user_level:   요청자 보안 등급 ("C" | "S" | "O")
        doc_level:    전송할 문서의 등급 ("C" | "S" | "O")
        target_level: 전송 목적지 영역 등급 ("C" | "S" | "O")

    Returns:
        tuple[bool, str]: (허용 여부, 사유 메시지)
    """
    user_level   = user_level.upper()
    doc_level    = doc_level.upper()
    target_level = target_level.upper()

    u_rank = _LEVEL_RANK.get(user_level, 0)
    d_rank = _LEVEL_RANK.get(doc_level, 0)

    # 규칙 1: 사용자 등급 < 문서 등급 → 전송 불가
    if u_rank < d_rank:
        return (
            False,
            f"transfer denied: user level '{user_level}' insufficient "
            f"for document level '{doc_level}'",
        )

    # 규칙 2: 정책 테이블 조회
    policy_key = (doc_level, target_level)
    allowed, _ = _TRANSFER_POLICY.get(policy_key, (False, False))

    if not allowed:
        return (
            False,
            f"transfer denied by policy: "
            f"doc_level='{doc_level}' → target='{target_level}' is not permitted",
        )

    return (
        True,
        f"transfer allowed: doc_level='{doc_level}' → target='{target_level}'",
    )


# ---------------------------------------------------------------------------
# 3. 전송용 본문 처리 함수
# ---------------------------------------------------------------------------

def sanitize_for_transfer(
    text: str,
    doc_level: str,
    user_level: str,
    target_level: str,
) -> dict[str, Any]:
    """
    전송 전 본문에 대한 마스킹 여부를 결정하고 처리한다.

    마스킹 적용 기준:
        - S 문서 → O 영역 전송 시 강제 마스킹 (mask_open_docs=True)
        - C 문서 → C 영역, S 문서 → S 영역, O 문서 → O 영역 전송 시 마스킹 없음
        - 그 외는 can_transfer() 단계에서 이미 차단됨

    Args:
        text:         원본 문서 본문
        doc_level:    문서 보안 등급
        user_level:   요청자 보안 등급
        target_level: 전송 목적지 등급

    Returns:
        filter_engine.mask_text() 반환 형식과 동일한 dict
    """
    doc_level    = doc_level.upper()
    user_level   = user_level.upper()
    target_level = target_level.upper()

    policy_key = (doc_level, target_level)
    _, force_mask = _TRANSFER_POLICY.get(policy_key, (False, False))

    # S→O 전송 시 강제 마스킹 (mask_open_docs=True로 O 문서도 마스킹)
    mask_open_docs = force_mask

    return filter_engine.mask_text(
        text=text,
        doc_level=doc_level,
        user_level=user_level,
        mask_open_docs=mask_open_docs,
    )


# ---------------------------------------------------------------------------
# 4. 핵심 전송 처리 함수
# ---------------------------------------------------------------------------

def transfer_document(
    doc: dict[str, str],
    user_level: str,
    target_level: str,
) -> dict[str, Any]:
    """
    문서 전송 요청을 처리하고 결과를 반환한다.

    처리 흐름:
        1. can_transfer() 로 정책 판단
        2. 허용 시 sanitize_for_transfer() 로 본문 처리
        3. 처리 결과를 표준 응답 형식으로 반환

    Args:
        doc: 전송 대상 문서 dict
            {
                "doc_id":    "S-001",
                "title":     "인사 평가 문서",
                "doc_level": "S",
                "content":   "..."
            }
        user_level:   요청자 보안 등급 ("C" | "S" | "O")
        target_level: 전송 목적지 등급 ("C" | "S" | "O")

    Returns:
        성공 시:
            {
                "success":        True,
                "allowed":        True,
                "doc_id":         "S-001",
                "title":          "인사 평가 문서",
                "doc_level":      "S",
                "user_level":     "S",
                "target_level":   "O",
                "sanitized_text": "마스킹된 본문",
                "masked_entities": [...],
                "message":        "transfer allowed with masking"
            }
        실패 시:
            {
                "success":        False,
                "allowed":        False,
                "doc_id":         "C-001",
                "title":          "기밀 문서",
                "doc_level":      "C",
                "user_level":     "S",
                "target_level":   "O",
                "sanitized_text": None,
                "masked_entities": [],
                "message":        "transfer denied by policy"
            }
    """
    user_level   = user_level.upper()
    target_level = target_level.upper()

    doc_id    = doc.get("doc_id", "UNKNOWN")
    title     = doc.get("title", "")
    doc_level = doc.get("doc_level", "").upper()
    content   = doc.get("content", "")

    # --- 정책 판단 ---
    allowed, reason = can_transfer(user_level, doc_level, target_level)

    if not allowed:
        return {
            "success":         False,
            "allowed":         False,
            "doc_id":          doc_id,
            "title":           title,
            "doc_level":       doc_level,
            "user_level":      user_level,
            "target_level":    target_level,
            "sanitized_text":  None,
            "masked_entities": [],
            "message":         reason,
        }

    # --- 본문 처리 (마스킹 or 원문) ---
    sanitize_result = sanitize_for_transfer(
        text=content,
        doc_level=doc_level,
        user_level=user_level,
        target_level=target_level,
    )

    # S→O 강제 마스킹 시 메시지 조정
    policy_key = (doc_level, target_level)
    _, force_mask = _TRANSFER_POLICY.get(policy_key, (False, False))
    final_message = (
        "transfer allowed with masking" if force_mask
        else "transfer allowed"
    )

    return {
        "success":         True,
        "allowed":         True,
        "doc_id":          doc_id,
        "title":           title,
        "doc_level":       doc_level,
        "user_level":      user_level,
        "target_level":    target_level,
        "sanitized_text":  sanitize_result.get("masked_text"),
        "masked_entities": sanitize_result.get("masked_entities", []),
        "message":         final_message,
    }


# ---------------------------------------------------------------------------
# 5. 감사 로그 구조 생성 함수
# ---------------------------------------------------------------------------

def build_transfer_audit_log(result: dict[str, Any]) -> dict[str, Any]:
    """
    transfer_document() 반환값을 받아 감사 로그용 dict를 생성한다.

    포함 필드:
        - timestamp    : ISO 8601 형식의 현재 시각 (UTC)
        - doc_id       : 문서 ID
        - doc_level    : 문서 등급
        - user_level   : 요청자 등급
        - target_level : 전송 목적지 등급
        - allowed      : 전송 허용 여부
        - message      : 처리 결과 메시지
        - entity_count : 탐지된 민감 엔티티 수 (허용된 경우)

    Args:
        result: transfer_document() 반환값

    Returns:
        감사 로그용 dict
        (추후 logger.py 의 write_audit_log() 에 전달할 구조)
    """
    entity_count = len(result.get("masked_entities") or [])

    return {
        "timestamp":    datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "doc_id":       result.get("doc_id"),
        "doc_level":    result.get("doc_level"),
        "user_level":   result.get("user_level"),
        "target_level": result.get("target_level"),
        "allowed":      result.get("allowed"),
        "message":      result.get("message"),
        "entity_count": entity_count,
    }
