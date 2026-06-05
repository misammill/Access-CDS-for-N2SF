"""
logger.py - CDS 감사 로그 기록 모듈

PoC 단계에서는 로컬 파일(JSON Lines 형식)에 로그를 저장한다.
JSON Lines: 한 줄 = 하나의 JSON 객체 → 나중에 파싱/분석이 용이하다.

파일 경로: ./logs/audit.log (CDS 실행 디렉토리 기준)

나중에 CloudWatch, S3, DB 등으로 교체할 때는
write_log() 내부만 수정하면 된다.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

from models import AuditLog, UserLevel

# 로그 파일 저장 디렉토리 및 파일명
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
LOG_FILE = os.path.join(LOG_DIR, "audit.jsonl")


def _ensure_log_dir() -> None:
    """로그 디렉토리가 없으면 생성한다."""
    os.makedirs(LOG_DIR, exist_ok=True)


def write_log(log: AuditLog) -> None:
    """
    AuditLog 객체를 JSON Lines 형식으로 파일에 기록한다.

    Args:
        log: 기록할 AuditLog 인스턴스
    """
    _ensure_log_dir()

    record = log.model_dump()
    # datetime 직렬화 (isoformat 문자열)
    record["timestamp"] = log.timestamp.isoformat()

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def log_access(
    user_id: str,
    user_level: UserLevel,
    doc_id: str,
    doc_level: UserLevel,
    result: str,
    reason: Optional[str] = None,
) -> None:
    """
    문서 조회 이벤트를 로그에 기록한다.

    Args:
        user_id:    요청 사용자 ID
        user_level: 요청 사용자 보안 등급
        doc_id:     조회 대상 문서 ID
        doc_level:  문서 보안 등급
        result:     처리 결과 ("allow" / "deny" / "masked")
        reason:     거부 또는 마스킹 사유 (선택)
    """
    log = AuditLog(
        event_type="ACCESS",
        user_id=user_id,
        user_level=user_level,
        doc_id=doc_id,
        action="READ",
        source_level=doc_level,   # 조회 시: source = 문서 등급
        target_level=None,        # 조회 시: target 없음
        result=result,
        reason=reason,
        timestamp=datetime.now(timezone.utc),
    )
    write_log(log)


def log_unauthenticated(
    doc_id: Optional[str],
    action: str,
    reason: str,
    source_level: Optional[UserLevel] = None,
) -> None:
    """
    인증 없이(또는 실패한) 보호 리소스 접근 시도를 로그에 기록한다.
    """
    log = AuditLog(
        event_type="DENIED",
        user_id="(unauthenticated)",
        user_level=None,
        doc_id=doc_id,
        action=action,
        source_level=source_level,
        target_level=None,
        result="deny",
        reason=reason,
        timestamp=datetime.now(timezone.utc),
    )
    write_log(log)


def log_transfer(
    user_id: str,
    user_level: UserLevel,
    doc_id: str,
    source_level: UserLevel,
    target_level: UserLevel,
    result: str,
    reason: Optional[str] = None,
) -> None:
    """
    문서 전송 이벤트를 로그에 기록한다.

    Args:
        user_id:      요청 사용자 ID
        user_level:   요청 사용자 보안 등급
        doc_id:       전송 대상 문서 ID
        source_level: 원본 도메인 등급
        target_level: 목적지 도메인 등급
        result:       처리 결과 ("allow" / "deny" / "masked")
        reason:       거부 또는 마스킹 사유 (선택)
    """
    log = AuditLog(
        event_type="TRANSFER",
        user_id=user_id,
        user_level=user_level,
        doc_id=doc_id,
        action="UPLOAD",
        source_level=source_level,
        target_level=target_level,
        result=result,
        reason=reason,
        timestamp=datetime.now(timezone.utc),
    )
    write_log(log)


def log_denied(
    user_id: str,
    user_level: UserLevel,
    doc_id: Optional[str],
    action: str,
    reason: str,
    source_level: Optional[UserLevel] = None,
    target_level: Optional[UserLevel] = None,
) -> None:
    """
    접근 거부 이벤트를 로그에 기록한다.
    접근·전송 정책 위반으로 거부된 경우 호출한다.

    Args:
        user_id:      요청 사용자 ID
        user_level:   요청 사용자 보안 등급
        doc_id:       대상 문서 ID (없으면 None)
        action:       시도한 액션 ("READ" / "UPLOAD" 등)
        reason:       거부 사유 설명
        source_level: 원본 등급 (선택)
        target_level: 목적지 등급 (선택)
    """
    log = AuditLog(
        event_type="DENIED",
        user_id=user_id,
        user_level=user_level,
        doc_id=doc_id,
        action=action,
        source_level=source_level,
        target_level=target_level,
        result="deny",
        reason=reason,
        timestamp=datetime.now(timezone.utc),
    )
    write_log(log)
