"""
auth.py - JWT 검증 및 사용자 등급 확인

PoC 단계에서는 로컬 secret 기반의 단순 JWT 검증을 사용한다.
실제 운영 시에는 외부 인증 서버(JWKS 등)로 교체 가능하도록
이 파일의 인터페이스(verify_token)만 유지하면 된다.

JWT Payload 예시:
{
  "sub": "user123",         # user_id
  "level": "S",             # user_level (C / S / O)
  "iat": 1712345678,
  "exp": 1712349278
}
"""

import os
from datetime import datetime

from dotenv import load_dotenv
from fastapi import HTTPException, status
from jose import JWTError, jwt

from models import UserContext, UserLevel

load_dotenv()

# PoC용 데모 시크릿. 실제 운영 시 환경변수로 교체한다.
SECRET_KEY = os.getenv("CDS_JWT_SECRET", "cds-demo-secret-key-2024")
ALGORITHM = "HS256"


def verify_token(token: str) -> UserContext:
    """
    JWT 토큰을 검증하고 UserContext를 반환한다.

    Args:
        token: Bearer 토큰 문자열 (앞의 "Bearer " 제거 후 전달)

    Returns:
        UserContext: 검증된 사용자 정보

    Raises:
        HTTPException 401: 토큰이 유효하지 않거나 만료된 경우
        HTTPException 400: 필수 필드(sub, level)가 없는 경우
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"유효하지 않은 토큰: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = _extract_user_id(payload)
    user_level = _extract_user_level(payload)
    issued_at = _extract_issued_at(payload)

    return UserContext(
        user_id=user_id,
        user_level=user_level,
        issued_at=issued_at,
    )


def _extract_user_id(payload: dict) -> str:
    """payload에서 user_id(sub)를 추출한다."""
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="토큰에 user_id(sub) 필드가 없습니다.",
        )
    return str(user_id)


def _extract_user_level(payload: dict) -> UserLevel:
    """payload에서 user_level을 추출하고 유효성을 검사한다."""
    level = payload.get("level")
    valid_levels = ("C", "S", "O")
    if level not in valid_levels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"유효하지 않은 사용자 등급: '{level}'. 허용값: {valid_levels}",
        )
    return level  # type: ignore[return-value]


def _extract_issued_at(payload: dict) -> datetime | None:
    """payload에서 발급 시각을 추출한다. 없으면 None 반환."""
    iat = payload.get("iat")
    if iat is None:
        return None
    try:
        return datetime.utcfromtimestamp(iat)
    except (TypeError, ValueError):
        return None


# -----------------------------------------------------------------
# 개발/테스트용 토큰 생성 유틸
# PoC 시연 시 임시 토큰 발급에 사용한다. 운영 코드에서는 제거한다.
# -----------------------------------------------------------------
def create_demo_token(user_id: str, user_level: UserLevel) -> str:
    """
    데모용 JWT 토큰을 생성한다. (테스트 전용)

    Args:
        user_id: 사용자 ID
        user_level: 사용자 보안 등급 (C / S / O)

    Returns:
        str: 서명된 JWT 토큰
    """
    import time
    payload = {
        "sub": user_id,
        "level": user_level,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # 1시간 유효
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
