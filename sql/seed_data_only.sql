-- 테이블·시퀀스가 이미 있을 때 샘플 데이터만 다시 채움
-- C##cds(데이터 스키마)로 접속한 뒤 실행하세요.

DELETE FROM documents;
DELETE FROM users;

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

COMMIT;
