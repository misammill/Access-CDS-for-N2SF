"""
models.py - CDS 공통 데이터 구조 정의

CDS 전체에서 공유하는 데이터 타입을 한 곳에서 관리한다.
Pydantic BaseModel 기반으로 FastAPI 요청/응답 타입과 자연스럽게 연동된다.
"""

from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field


# -----------------------------------------------------------------
# 사용자 등급 타입
# C (Confidential) > S (Secret) > O (Open) 순서로 보안 등급이 높음
# -----------------------------------------------------------------
UserLevel = Literal["C", "S", "O"]


# -----------------------------------------------------------------
# UserContext
# JWT 토큰 검증 후 추출된 사용자 컨텍스트
# auth.py에서 생성하여 각 서비스로 전달한다
# -----------------------------------------------------------------
class UserContext(BaseModel):
    user_id: str
    user_level: UserLevel
    issued_at: Optional[datetime] = None


# -----------------------------------------------------------------
# DocumentMeta
# S3에 저장된 문서의 메타정보
# access_service, transfer_service에서 사용 예정
# -----------------------------------------------------------------
class DocumentMeta(BaseModel):
    doc_id: str
    file_name: str
    doc_level: UserLevel          # 문서 자체의 보안 등급
    owner_id: str
    s3_bucket: str
    s3_key: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


# -----------------------------------------------------------------
# AuditLog
# 접근 및 전송 이벤트 로그 레코드
# logger.py에서 생성하여 저장소(로컬 파일 또는 S3)에 기록한다
# -----------------------------------------------------------------
class AuditLog(BaseModel):
    event_type: Literal["ACCESS", "TRANSFER", "DENIED"]
    user_id: str
    user_level: Optional[UserLevel] = None  # 미인증 시 None
    doc_id: Optional[str] = None
    action: str                              # 예: "READ", "UPLOAD"
    source_level: Optional[UserLevel] = None # 전송 시 원본 등급
    target_level: Optional[UserLevel] = None # 전송 시 목적지 등급
    result: Literal["allow", "deny", "masked"]  # logger.py 결과값과 통일
    reason: Optional[str] = None             # 거부/마스킹 사유
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# -----------------------------------------------------------------
# AccessRequest
# 사용자가 문서를 조회할 때 CDS로 보내는 요청 구조
# access_service.py에서 처리 예정
# -----------------------------------------------------------------
class AccessRequest(BaseModel):
    doc_id: str
    requester_token: str          # JWT 토큰 (auth.py로 전달)


# -----------------------------------------------------------------
# TransferRequest
# 사용자가 문서를 업로드/전송할 때 CDS로 보내는 요청 구조
# transfer_service.py에서 처리 예정
# -----------------------------------------------------------------
class TransferRequest(BaseModel):
    file_name: str
    doc_level: UserLevel          # 업로드하려는 문서의 목표 등급
    requester_token: str          # JWT 토큰 (auth.py로 전달)
    content: str                  # 파일 내용 (PoC 단계: base64 또는 raw 텍스트)
