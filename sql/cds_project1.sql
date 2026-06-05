-- CDS Oracle 스키마 + 초기 샘플 데이터
-- C##cds 등 데이터 스키마로 접속한 뒤 실행하세요.

CREATE TABLE users (
  user_id VARCHAR2(50) PRIMARY KEY,
  password VARCHAR2(255) NOT NULL,
  name VARCHAR2(50) NOT NULL,
  role CHAR(1) NOT NULL,
  otp_secret VARCHAR2(255),
  created_at DATE DEFAULT SYSDATE
);

CREATE TABLE documents (
  doc_id NUMBER PRIMARY KEY,
  title VARCHAR2(200) NOT NULL,
  doc_level CHAR(1) NOT NULL,
  file_name VARCHAR2(255),
  file_path VARCHAR2(500),
  created_at DATE DEFAULT SYSDATE
);

CREATE SEQUENCE doc_seq START WITH 1 INCREMENT BY 1;

INSERT INTO users (user_id, password, name, role)
VALUES ('admin', '1234', '관리자', 'C');

INSERT INTO users (user_id, password, name, role)
VALUES ('staff1', '1234', '직원', 'S');

INSERT INTO users (user_id, password, name, role)
VALUES ('user1', '1234', '일반사용자', 'O');

INSERT INTO documents (doc_id, title, doc_level, file_name, file_path)
VALUES (doc_seq.NEXTVAL, '공지사항', 'O', 'notice.pdf', 's3/open/notice.pdf');

INSERT INTO documents (doc_id, title, doc_level, file_name, file_path)
VALUES (doc_seq.NEXTVAL, '업무 계획서', 'S', 'plan.pdf', 's3/sensitive/plan.pdf');

INSERT INTO documents (doc_id, title, doc_level, file_name, file_path)
VALUES (doc_seq.NEXTVAL, '기밀 보고서', 'C', 'secret.pdf', 's3/classified/secret.pdf');

-- 최초 로그인 시 OTP QR 등록을 위해 비워 둠
UPDATE users SET otp_secret = NULL WHERE TRIM(user_id) IN ('admin', 'staff1', 'user1');

COMMIT;
