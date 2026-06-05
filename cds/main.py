"""
main.py - CDS FastAPI 애플리케이션 시작점

엔드포인트 구성:
    [인증 불필요]
    GET  /health              → 서버 상태 확인
    POST /demo/token          → 데모용 JWT 발급 (PoC 전용)
    GET  /demo/verify         → JWT 검증 테스트 (PoC 전용)

    [JWT 인증 필요 - Authorization: Bearer <token>]
    GET  /documents/s3-index  → C/S/O S3 버킷 객체 목록 통합 (웹 목록용)
    GET  /access/{doc_id}     → 문서 조회 (access_service)
    POST /transfer            → 문서 전송 (transfer_service)
    GET  /audit/logs          → 최근 감사 로그 조회

흐름 요약:
    요청 → JWT 검증(auth.py) → 서비스 처리 → 감사 로그 기록(logger.py) → 응답
"""

import json
import os
from typing import Optional
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

import access_service
import logger
import transfer_service
from auth import create_demo_token, verify_token
from models import UserContext, UserLevel

# ---------------------------------------------------------------------------
# 앱 초기화
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CDS (Cross Domain Solution) API",
    description="""
## N2SF 기반 CDS 프로토타입 - PoC 버전

### 사용 방법
1. `/demo/token` 으로 JWT 토큰 발급
2. 우측 상단 **Authorize 🔒** 버튼 클릭 → 토큰 붙여넣기
3. `/access/{doc_id}` 또는 `/transfer` 호출

### 보안 등급 (조회)
| 사용자 \\ 문서 | C | S | O |
|---------------|---|---|---|
| C | 원문 | 원문 | 원문 |
| S | **마스킹** | 원문 | 원문 |
| O | **마스킹** | **마스킹** | 원문 |

사용자 등급이 문서 등급보다 낮으면 403 차단 없이 마스킹본을 반환합니다.

### 문서 ID
- 웹 목록·실서비스: `/documents/s3-index` 가 반환하는 `s3r1.*` 참조
- API 테스트용(인메모리): `C-001`, `S-001`, `O-001`
    """,
    version="0.2.0",
)

# 웹 프론트엔드(포트 3000)에서의 직접 API 호출을 허용한다.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Swagger UI 자물쇠 버튼용 Bearer 스킴
http_bearer = HTTPBearer()
# 문서 접근: 토큰 없을 때 감사 로그를 남긴 뒤 401 반환
http_bearer_optional = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
) -> UserContext:
    """
    JWT 토큰을 검증하고 현재 사용자 컨텍스트를 반환하는 의존성 함수.
    인증이 필요한 모든 엔드포인트에서 Depends(get_current_user)로 사용한다.
    """
    return verify_token(credentials.credentials)


def _audit_auth_failure(doc_id: str, action: str, reason: str) -> None:
    """미인증·인증 실패 시 문서 등급(알 수 있으면)과 함께 감사 로그를 남긴다."""
    doc = access_service.get_document(doc_id)
    source_level = doc.get("doc_level") if doc else None
    logger.log_unauthenticated(
        doc_id=doc_id,
        action=action,
        reason=reason,
        source_level=source_level,  # type: ignore[arg-type]
    )


def get_current_user_for_doc_access(
    doc_id: str,
    credentials: HTTPAuthorizationCredentials | None = Depends(http_bearer_optional),
) -> UserContext:
    """
    GET /access/{doc_id} 전용: 토큰 없음·무효 시 감사 로그 기록 후 401.
    """
    if credentials is None:
        _audit_auth_failure(doc_id, "READ", "인증 토큰 없음")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return verify_token(credentials.credentials)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            _audit_auth_failure(doc_id, "READ", f"인증 실패: {exc.detail}")
        raise


# ---------------------------------------------------------------------------
# 요청/응답 스키마 (Pydantic)
# ---------------------------------------------------------------------------

class TransferRequestBody(BaseModel):
    """POST /transfer 요청 바디"""
    doc_id: str
    target_level: UserLevel

    model_config = {
        "json_schema_extra": {
            "example": {
                "doc_id": "S-001",
                "target_level": "O"
            }
        }
    }


class AccessResponse(BaseModel):
    """GET /access/{doc_id} 응답"""
    success: bool
    doc_id: str
    title: Optional[str]
    doc_level: Optional[str]
    user_id: str
    user_level: str
    allowed: bool
    masked_text: Optional[str]
    masked_count: int
    message: str
    masked_docx_available: bool = False


class TransferResponse(BaseModel):
    """POST /transfer 응답"""
    success: bool
    doc_id: str
    title: Optional[str]
    doc_level: Optional[str]
    user_id: str
    user_level: str
    target_level: str
    allowed: bool
    sanitized_text: Optional[str]
    masked_count: int
    message: str


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["시스템"])
def health_check():
    """서버 상태를 확인한다."""
    return {"status": "ok", "service": "CDS", "version": "0.2.0"}


# ---------------------------------------------------------------------------
# 데모용 엔드포인트 (PoC 전용)
# ---------------------------------------------------------------------------

@app.post("/demo/token", tags=["데모 (PoC 전용)"])
def issue_demo_token(user_id: str, user_level: UserLevel):
    """
    데모용 JWT 토큰을 발급한다. (테스트 전용, 운영에서는 제거)

    - **user_id**: 사용자 식별자 (예: `user001`)
    - **user_level**: 보안 등급 (`C` / `S` / `O`)
    """
    token = create_demo_token(user_id=user_id, user_level=user_level)
    return {
        "access_token": token,
        "token_type": "bearer",
        "tip": "Swagger 우측 상단 🔒 Authorize 버튼에 이 토큰을 붙여넣으세요.",
    }


@app.get("/demo/verify", response_model=UserContext, tags=["데모 (PoC 전용)"])
def verify_token_demo(user: UserContext = Depends(get_current_user)):
    """
    JWT를 검증하고 파싱된 UserContext를 반환한다. (토큰 확인용)
    """
    return user


# ---------------------------------------------------------------------------
# S3 통합 목록 (웹 문서 화면)
# ---------------------------------------------------------------------------


@app.get("/documents/s3-index", tags=["CDS 핵심 기능"], summary="S3 통합 문서 목록")
def list_s3_documents_index(
    page: int = Query(default=1, ge=1, description="페이지 (1부터)"),
    page_size: int = Query(default=10, ge=1, le=100, description="페이지당 행 수"),
    max_per_bucket: int = Query(default=50, ge=1, le=2000, description="버킷당 최대 객체 수(목록 합친 뒤 페이지 분할)"),
    user: UserContext = Depends(get_current_user),
):
    """
    n2sf-c / n2sf-s / n2sf-o(또는 환경 변수로 지정한 등급별 버킷)의 객체를 한 목록으로 합친 뒤 페이지로 잘라 반환한다.

    - **doc_id**: 이후 `GET /access/{doc_id}` 에 그대로 넣을 수 있는 참조(`s3r1.` 접두사)
    - 웹에서는 JWT(웹 로그인 토큰)을 Authorization 헤더에 넣어 호출한다.
    """
    from s3_inventory import list_combined_s3_documents

    items = list_combined_s3_documents(max_per_bucket=max_per_bucket)
    total = len(items)
    start = (page - 1) * page_size
    data = items[start : start + page_size]
    return {
        "source": "s3",
        "total": total,
        "page": page,
        "page_size": page_size,
        "count": len(data),
        "data": data,
    }


@app.get("/access/{doc_id}/download-masked", tags=["CDS 핵심 기능"], summary="마스킹된 Word 다운로드")
def download_masked_docx(
    doc_id: str,
    user: UserContext = Depends(get_current_user_for_doc_access),
):
    """
    S3 `s3r1.*` 참조가 가리키는 .docx를 읽어, 단락 단위 마스킹을 적용한 새 파일을 내려준다.
    열람 권한은 `GET /access/{doc_id}` 와 동일하게 검사한다.
    """
    from docx_mask import build_masked_docx_bytes
    from s3_inventory import load_s3_ref_object_bytes

    resolved = load_s3_ref_object_bytes(doc_id)
    if resolved is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="문서를 찾을 수 없습니다.",
        )
    _bucket, s3_key, doc_level, title, raw = resolved
    if not s3_key.lower().endswith(".docx"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Word(.docx)만 마스킹 다운로드할 수 있습니다.",
        )

    gate = access_service.access_document(doc_id=doc_id, user_level=user.user_level)
    if not gate.get("success") or gate.get("message") == "document not found":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="문서를 찾을 수 없습니다.",
        )
    if not gate.get("allowed"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=gate.get("message") or "문서 처리 엔진을 사용할 수 없습니다.",
        )

    try:
        masked = build_masked_docx_bytes(raw, doc_level=doc_level, user_level=user.user_level)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"문서 처리 실패: {e}",
        ) from e

    logger.log_access(
        user_id=user.user_id,
        user_level=user.user_level,
        doc_id=doc_id,
        doc_level=doc_level,
        result="masked",
        reason="masked_docx_download",
    )

    base = title.rsplit(".", 1)[0] if "." in title else title
    utf_name = f"{base}-masked.docx"
    ascii_fallback = "masked.docx"
    disp = (
        f'attachment; filename="{ascii_fallback}"; '
        f"filename*=UTF-8''{quote(utf_name)}"
    )

    return Response(
        content=masked,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": disp},
    )


# ---------------------------------------------------------------------------
# 문서 조회 엔드포인트
# ---------------------------------------------------------------------------

@app.get(
    "/access/{doc_id}",
    response_model=AccessResponse,
    tags=["CDS 핵심 기능"],
    summary="문서 조회",
)
def access_document(
    doc_id: str,
    user: UserContext = Depends(get_current_user_for_doc_access),
):
    """
    사용자의 보안 등급에 따라 문서를 조회한다.

    - 사용자 등급 ≥ 문서 등급 → **원문** 반환
    - 사용자 등급 < 문서 등급 → **마스킹** 후 반환 (403 없음)
    - 감사 로그 자동 기록

    **doc_id**: `/documents/s3-index` 의 `s3r1.*` 참조 또는 PoC 샘플 `C-001` 등
    """
    result = access_service.access_document(
        doc_id=doc_id,
        user_level=user.user_level,
    )

    # 감사 로그 기록
    if result["doc_level"] and result["allowed"]:
        log_result = "masked" if result["masked_entities"] else "allow"
        logger.log_access(
            user_id=user.user_id,
            user_level=user.user_level,
            doc_id=doc_id,
            doc_level=result["doc_level"],
            result=log_result,
            reason=result["message"] if log_result == "masked" else None,
        )

    # 문서 미존재 시 404
    if not result["success"] and result["message"] == "document not found":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"문서를 찾을 수 없습니다: {doc_id}",
        )

    masked_docx_available = bool(
        result.get("allowed")
        and result.get("s3_source_format") == "docx"
    )

    return AccessResponse(
        success=result["success"],
        doc_id=result["doc_id"],
        title=result["title"],
        doc_level=result["doc_level"],
        user_id=user.user_id,
        user_level=user.user_level,
        allowed=result["allowed"],
        masked_text=result["masked_text"],
        masked_count=len(result.get("masked_entities", [])),
        message=result["message"],
        masked_docx_available=masked_docx_available,
    )


# ---------------------------------------------------------------------------
# 문서 전송 엔드포인트
# ---------------------------------------------------------------------------

@app.post(
    "/transfer",
    response_model=TransferResponse,
    tags=["CDS 핵심 기능"],
    summary="문서 전송",
)
def transfer_document(
    body: TransferRequestBody,
    user: UserContext = Depends(get_current_user),
):
    """
    문서를 다른 보안 등급 영역으로 전송한다.

    전송 정책:
    | 문서 등급 | 목적지 | 결과 |
    |-----------|--------|------|
    | C → C | 허용 |
    | C → S/O | **차단** |
    | S → S | 허용 |
    | S → O | 허용 + **강제 마스킹** |
    | S → C | **차단** |
    | O → O | 허용 |
    | O → S/C | **차단** |

    - 감사 로그 자동 기록
    - **doc_id**: `s3r1.*` (S3) 또는 `C-001` 등 인메모리 샘플
    """
    doc = access_service.get_document(body.doc_id)
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"문서를 찾을 수 없습니다: {body.doc_id}",
        )

    result = transfer_service.transfer_document(
        doc=doc,
        user_level=user.user_level,
        target_level=body.target_level,
    )

    # 감사 로그 기록
    doc_level = result.get("doc_level")
    if doc_level:
        if result["allowed"]:
            log_result = "masked" if result["masked_entities"] else "allow"
            logger.log_transfer(
                user_id=user.user_id,
                user_level=user.user_level,
                doc_id=body.doc_id,
                source_level=doc_level,
                target_level=body.target_level,
                result=log_result,
                reason=result["message"] if log_result == "masked" else None,
            )
        else:
            logger.log_denied(
                user_id=user.user_id,
                user_level=user.user_level,
                doc_id=body.doc_id,
                action="UPLOAD",
                reason=result["message"],
                source_level=doc_level,
                target_level=body.target_level,
            )

    # 정책 위반으로 차단된 경우 403 반환
    if not result["allowed"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=result["message"],
        )

    return TransferResponse(
        success=result["success"],
        doc_id=result["doc_id"],
        title=result.get("title"),
        doc_level=result["doc_level"],
        user_id=user.user_id,
        user_level=user.user_level,
        target_level=result["target_level"],
        allowed=result["allowed"],
        sanitized_text=result.get("sanitized_text"),
        masked_count=len(result.get("masked_entities", [])),
        message=result["message"],
    )


# ---------------------------------------------------------------------------
# 감사 로그 조회 엔드포인트
# ---------------------------------------------------------------------------

@app.get("/audit/logs", tags=["감사 로그"])
def get_audit_logs(
    limit: int = Query(default=20, ge=1, le=100, description="최근 N개 로그 조회"),
    user: UserContext = Depends(get_current_user),
):
    """
    최근 감사 로그를 조회한다. (C 등급 사용자만 전체 로그 접근 가능)

    - **limit**: 최근 몇 건을 조회할지 (1~100, 기본값 20)
    """
    if user.user_level != "C":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="감사 로그는 C 등급 사용자만 조회할 수 있습니다.",
        )

    log_file = os.path.join(os.path.dirname(__file__), "logs", "audit.jsonl")

    if not os.path.exists(log_file):
        return {"logs": [], "count": 0, "message": "아직 기록된 로그가 없습니다."}

    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # 최신 N건 반환
    recent_lines = lines[-limit:]
    logs = [json.loads(line.strip()) for line in recent_lines if line.strip()]

    return {
        "logs": list(reversed(logs)),  # 최신이 위로
        "count": len(logs),
        "total_records": len(lines),
    }
