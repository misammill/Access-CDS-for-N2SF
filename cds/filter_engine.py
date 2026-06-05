"""
filter_engine.py
================
Presidio 기반 개인정보/민감정보 탐지 및 익명화 엔진 (PoC/데모용)

Requirements:
    pip install presidio_analyzer presidio_anonymizer
    python -m spacy download en_core_web_lg  # 또는 en_core_web_sm

Usage (FastAPI 예시):
    from filter_engine import mask_text
    result = mask_text(text, doc_level="S", user_level="C")
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# 1. 등급 Enum
# ---------------------------------------------------------------------------

class DocumentLevel(str, Enum):
    """문서 보안 등급. C > S > O 순으로 높음."""
    C = "C"  # 기밀 (Confidential)
    S = "S"  # 민감 (Sensitive)
    O = "O"  # 공개 (Open)


class UserLevel(str, Enum):
    """사용자 보안 등급. C > S > O 순으로 높음."""
    C = "C"
    S = "S"
    O = "O"


# 등급 우선순위 (숫자가 클수록 높은 등급)
_LEVEL_RANK: dict[str, int] = {"C": 3, "S": 2, "O": 1}


# ---------------------------------------------------------------------------
# 2. 접근 판단
# ---------------------------------------------------------------------------

def can_view(user_level: str, doc_level: str) -> bool:
    """
    사용자가 해당 문서를 **원문(비마스킹)** 으로 조회할 수 있는지 판단한다.

    정책: user_level 순위 >= doc_level 순위 → 원문 허용
          user_level 순위 <  doc_level 순위 → 원문 불가 (마스킹본은 반환 가능)

    Args:
        user_level: 사용자 등급 ("C" | "S" | "O")
        doc_level:  문서 등급  ("C" | "S" | "O")

    Returns:
        True if unmasked access is allowed, False if masking is required.
    """
    u_rank = _LEVEL_RANK.get(user_level.upper(), 0)
    d_rank = _LEVEL_RANK.get(doc_level.upper(), 0)
    return u_rank >= d_rank


def needs_masking_on_access(user_level: str, doc_level: str) -> bool:
    """조회 시 Presidio 마스킹이 필요한지 (user < doc)."""
    return not can_view(user_level, doc_level)


# ---------------------------------------------------------------------------
# 3. Presidio 엔진 빌더
# ---------------------------------------------------------------------------

def build_analyzer_engine():
    """
    Presidio AnalyzerEngine을 생성하고 한국형 커스텀 Recognizer를 등록한다.

    커스텀 Recognizer:
        - KOREAN_RRN   : 주민등록번호 (990101-1234567)
        - KOREAN_PHONE : 한국 전화번호 (010-1234-5678, 02-123-4567)
        - ACCOUNT_NUMBER: 은행 계좌번호 형태 숫자열

    Returns:
        AnalyzerEngine 인스턴스
    """
    try:
        from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    except ImportError as e:
        raise ImportError(
            "presidio_analyzer 패키지가 필요합니다. "
            "`pip install presidio_analyzer` 를 실행하세요."
        ) from e

    # --- 한국형 커스텀 Recognizer ---
    # supported_language="en" 으로 설정해야 analyzer.analyze(language="en") 호출 시
    # 레지스트리에서 정상 조회됨 (Presidio 기본 언어 필터 정책)

    # 주민등록번호: YYMMDD-NNNNNNN (앞 6자리-뒤 7자리)
    rrn_recognizer = PatternRecognizer(
        supported_entity="KOREAN_RRN",
        supported_language="en",
        patterns=[
            Pattern(
                name="korean_rrn",
                regex=r"\b\d{6}-[1-4]\d{6}\b",
                score=0.95,
            )
        ],
    )

    # 한국 전화번호: 010-XXXX-XXXX / 02-XXX-XXXX / 031-XXX-XXXX 등
    phone_recognizer = PatternRecognizer(
        supported_entity="KOREAN_PHONE",
        supported_language="en",
        patterns=[
            Pattern(
                name="korean_mobile",
                regex=r"\b01[016789]-\d{3,4}-\d{4}\b",
                score=0.90,
            ),
            Pattern(
                name="korean_landline",
                regex=r"\b0\d{1,2}-\d{3,4}-\d{4}\b",
                score=0.85,
            ),
        ],
    )

    # 계좌번호: 은행별로 다양하나 숫자-숫자 형태 (10~14자리 연속 또는 구분자 포함)
    account_recognizer = PatternRecognizer(
        supported_entity="ACCOUNT_NUMBER",
        supported_language="en",
        patterns=[
            Pattern(
                name="account_number_hyphen",
                regex=r"\b\d{3,6}-\d{2,6}-\d{4,6}(-\d{2})?\b",
                score=0.80,
            ),
            Pattern(
                name="account_number_plain",
                regex=r"\b\d{10,14}\b",
                score=0.55,  # 낮은 스코어 (오탐 가능성 있음)
            ),
        ],
    )

    # 한국어 이름 인식기
    # 원리: 한국 성씨(1글자) + 이름(2글자) 조합을 탐지 → 3글자 이름만 인식
    #   - (?<![가-힣]) : 바로 앞이 한국어 글자면 제외 (예: "인사팀장"의 "장" 오탐 방지)
    #   - [가-힣]{2}   : 이름 2글자 필수 → "이상", "성명" 같은 2글자 단어 제외
    #   - (?![가-힣])  : 바로 뒤가 한국어 글자면 제외
    # context 단어(직책/역할/레이블) 근처에서 신뢰도가 자동으로 상향된다 (Presidio 정책)
    _KOREAN_SURNAMES = (
        r"김|이|박|최|정|강|조|윤|장|임|한|오|서|신|권|황|안|송|홍|"
        r"고|문|양|손|배|백|허|유|남|심|노|하|곽|성|차|주|우|구|민|"
        r"나|지|엄|채|원|천|방|공"
    )
    korean_name_recognizer = PatternRecognizer(
        supported_entity="KOREAN_NAME",
        supported_language="en",
        patterns=[
            Pattern(
                name="korean_name_3char",
                # {2}: 이름 부분 정확히 2글자 → 총 3글자 이름만 탐지
                # "이상"(2글자), "성명"(2글자) 등 2글자 단어 자동 제외
                regex=rf"(?<![가-힣])(?:{_KOREAN_SURNAMES})[가-힣]{{2}}(?![가-힣])",
                # 0.85: 컨텍스트 부스트 없어도 body threshold(0.75) 통과
                # 표 셀(헤더와 데이터 분리)·본문 모두 잡히도록 자체 점수를 충분히 올린다.
                # 오탐은 _FALSE_POSITIVE_WORDS / _PARTICLE_TAIL 사후 필터로 차단한다.
                score=0.85,
            ),
        ],
        # 직책/역할/레이블 단어가 근처에 있으면 Presidio가 score를 상향
        # → "성명: 홍길동" 에서 "성명"이 있으면 "홍길동" 탐지 신뢰도 상승
        context=[
            "팀장", "부장", "과장", "대리", "사원", "담당자",
            "이사", "본부장", "대표", "직원", "참석자", "인사",
            "성명", "이름", "대상자", "작성자",
        ],
    )

    analyzer = AnalyzerEngine()
    registry = analyzer.registry

    registry.add_recognizer(rrn_recognizer)
    registry.add_recognizer(phone_recognizer)
    registry.add_recognizer(account_recognizer)
    registry.add_recognizer(korean_name_recognizer)

    return analyzer


def build_anonymizer_engine():
    """
    Presidio AnonymizerEngine을 생성한다.

    마스킹 전략:
        - PERSON           -> [NAME]
        - EMAIL_ADDRESS    -> [EMAIL]
        - CREDIT_CARD      -> **** 전체 마스킹
        - KOREAN_RRN       -> XXXXXX-XXXXXXX (거의 전체)
        - KOREAN_PHONE     -> 뒤 4자리 마스킹
        - PHONE_NUMBER     -> 뒤 4자리 마스킹
        - ACCOUNT_NUMBER   -> **** 전체 마스킹
        - DEFAULT          -> [REDACTED]

    Returns:
        AnonymizerEngine 인스턴스
    """
    try:
        from presidio_anonymizer import AnonymizerEngine
    except ImportError as e:
        raise ImportError(
            "presidio_anonymizer 패키지가 필요합니다. "
            "`pip install presidio_anonymizer` 를 실행하세요."
        ) from e

    return AnonymizerEngine()


def _build_operators() -> dict[str, Any]:
    """
    엔티티별 AnonymizerConfig(operator) 딕셔너리를 반환한다.
    OperatorConfig는 anonymize() 호출 시 operators 파라미터에 전달된다.
    """
    from presidio_anonymizer.entities import OperatorConfig

    return {
        "PERSON": OperatorConfig("replace", {"new_value": "[NAME]"}),
        "KOREAN_NAME": OperatorConfig("replace", {"new_value": "[NAME]"}),
        "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "[EMAIL]"}),
        "LOCATION": OperatorConfig("replace", {"new_value": "[LOCATION]"}),
        "CREDIT_CARD": OperatorConfig("mask", {
            "type": "mask",
            "masking_char": "*",
            "chars_to_mask": 16,
            "from_end": False,
        }),
        "KOREAN_RRN": OperatorConfig("replace", {"new_value": "XXXXXX-XXXXXXX"}),
        "KOREAN_PHONE": OperatorConfig("mask", {
            "type": "mask",
            "masking_char": "*",
            "chars_to_mask": 4,
            "from_end": True,
        }),
        "PHONE_NUMBER": OperatorConfig("mask", {
            "type": "mask",
            "masking_char": "*",
            "chars_to_mask": 4,
            "from_end": True,
        }),
        "ACCOUNT_NUMBER": OperatorConfig("mask", {
            "type": "mask",
            "masking_char": "*",
            "chars_to_mask": 8,
            "from_end": True,
        }),
        "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
    }


# ---------------------------------------------------------------------------
# 4. 엔진 싱글턴 (모듈 로드 시 1회만 초기화)
# ---------------------------------------------------------------------------

try:
    _ANALYZER = build_analyzer_engine()
    _ANONYMIZER = build_anonymizer_engine()
    _OPERATORS = _build_operators()
    _ENGINE_READY = True
    _ENGINE_ERROR: str | None = None
except Exception as _exc:
    _ANALYZER = None  # type: ignore[assignment]
    _ANONYMIZER = None  # type: ignore[assignment]
    _OPERATORS = {}
    _ENGINE_READY = False
    _ENGINE_ERROR = str(_exc)


# ---------------------------------------------------------------------------
# 5. 핵심 함수 mask_text()
# ---------------------------------------------------------------------------

def mask_text(
    text: str,
    doc_level: str,
    user_level: str,
    mask_open_docs: bool = False,
    score_threshold: float = 0.75,
) -> dict[str, Any]:
    """
    텍스트의 등급 기반 접근 제어 및 민감정보 마스킹을 수행한다.

    Args:
        text:             원본 텍스트
        doc_level:        문서 등급 ("C" | "S" | "O")
        user_level:       사용자 등급 ("C" | "S" | "O")
        mask_open_docs:   O 등급 문서를 마스킹할지 여부 (기본값 False)
        score_threshold:  탐지 신뢰도 최솟값 (기본 0.75, 표 셀 등 컨텍스트 없는 경우 낮춤)

    Returns:
        dict:
            - allowed (bool): 접근 허용 여부
            - doc_level (str): 문서 등급
            - user_level (str): 사용자 등급
            - original_text (str | None): 원본 텍스트 (차단 시 None)
            - masked_text (str | None): 마스킹된 텍스트 (차단 시 None)
            - masked_entities (list): 탐지된 엔티티 목록
            - message (str): 처리 결과 메시지
    """
    doc_level = doc_level.upper()
    user_level = user_level.upper()

    # 엔진 초기화 실패 시 에러 반환
    if not _ENGINE_READY:
        return {
            "allowed": False,
            "doc_level": doc_level,
            "user_level": user_level,
            "original_text": None,
            "masked_text": None,
            "masked_entities": [],
            "message": f"엔진 초기화 실패: {_ENGINE_ERROR}",
        }

    # ------- 원문 반환 (user 등급 >= doc 등급) -------
    if can_view(user_level, doc_level) and not (
        doc_level == "O" and mask_open_docs
    ):
        return {
            "allowed": True,
            "doc_level": doc_level,
            "user_level": user_level,
            "original_text": text,
            "masked_text": text,
            "masked_entities": [],
            "message": "full access granted",
        }

    # ------- 등급 미달: Presidio 마스킹 후 반환 (차단 없음) -------
    try:
        analysis_results = _ANALYZER.analyze(
            text=text,
            language="en",
            score_threshold=score_threshold,
            # PERSON 제거: 영어 SpaCy NLP 기반이라 한국어에서 심각한 오탐 발생
            # → 한국어 이름은 KOREAN_NAME(커스텀 인식기)으로만 탐지
            entities=[
                "EMAIL_ADDRESS", "PHONE_NUMBER",
                "CREDIT_CARD", "DATE_TIME", "LOCATION",
                "KOREAN_RRN", "KOREAN_PHONE", "ACCOUNT_NUMBER",
                "KOREAN_NAME",
            ],
        )

        # --- 알려진 오탐 단어 KOREAN_NAME 제거 ---
        # 한국어 시간/일반 단어 중 성씨+2글자 패턴과 겹치는 것들
        # score=0.85 로 올리면서 컨텍스트 부스트 없이도 통과하므로
        # 오탐 가능성이 있는 일반 단어를 충분히 누적해 둔다.
        _FALSE_POSITIVE_WORDS = {
            "하반기", "상반기", "정기적", "대상자", "채용계",
            "고려해", "고려한", "고려할", "고려해서",
            "남기는", "남겼다", "남겨서",
            "허락한", "허락해", "허락할",
            "이상의", "이상은", "이상이", "이하의",
            "방침이", "방침은", "방침을",
            "백지화", "한정적", "한정된",
            "조정이", "조정의", "조정한",
            "정리한", "정리해", "정리할",
            "구분이", "구분을", "구분한",
            "주의해", "주의할", "주의한",
            "신청한", "신청해", "신청할",
            "임의로", "임의의", "임의적",
            "지정한", "지정해", "지정할",
            "심사한", "심사해", "심사할",
            "안내해", "안내한", "안내할",
            "송부한", "송부해", "송부할",
        }
        _PARTICLE_TAIL = re.compile(r"[를을이가는은에서로과와의도만]$")
        analysis_results = [
            r for r in analysis_results
            if not (
                r.entity_type == "KOREAN_NAME"
                and (
                    _PARTICLE_TAIL.search(text[r.start:r.end])
                    or text[r.start:r.end] in _FALSE_POSITIVE_WORDS
                )
            )
        ]

        anonymized = _ANONYMIZER.anonymize(
            text=text,
            analyzer_results=analysis_results,
            operators=_OPERATORS,
        )

        masked_entities = [
            {
                "entity_type": r.entity_type,
                "start": r.start,
                "end": r.end,
                "score": round(r.score, 3),
                "text": text[r.start:r.end],
            }
            for r in analysis_results
        ]

        return {
            "allowed": True,
            "doc_level": doc_level,
            "user_level": user_level,
            "original_text": text,
            "masked_text": anonymized.text,
            "masked_entities": masked_entities,
            "message": "masked due to insufficient clearance",
        }

    except Exception as exc:
        return {
            "allowed": True,
            "doc_level": doc_level,
            "user_level": user_level,
            "original_text": text,
            "masked_text": None,
            "masked_entities": [],
            "message": f"마스킹 처리 중 오류 발생: {exc}",
        }
