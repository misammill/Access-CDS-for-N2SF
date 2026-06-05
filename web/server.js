const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");

const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const oracledb = require("oracledb");

const app = express();
app.use(cors());
app.use(express.json());

/** CDS(FastAPI) 기본 주소. 브라우저는 이 주소로 직접 가지 않고 /api/cds 로만 호출한다. */
const CDS_API_URL = String(process.env.CDS_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

const SECRET_KEY = process.env.CDS_JWT_SECRET || "cds-demo-secret-key-2024";

const oracleConfig = {
  user: process.env.ORACLE_USER || "cds",
  password: process.env.ORACLE_PASSWORD || "1234",
  connectString: process.env.ORACLE_CONNECT_STRING || "localhost:1521/XEPDB1"
};

function getConnection() {
  return oracledb.getConnection(oracleConfig);
}

async function closeQuietly(conn) {
  if (!conn) {
    return;
  }
  try {
    await conn.close();
  } catch (_) {}
}

function loginCredentials(req) {
  const raw = req.body || {};
  return {
    id: String(raw.id ?? "").trim(),
    pw: String(raw.pw ?? raw.password ?? "").trim()
  };
}

function firstCell(row) {
  if (row == null) {
    return undefined;
  }
  if (Array.isArray(row)) {
    return row[0];
  }
  const vals = Object.values(row);
  return vals.length ? vals[0] : undefined;
}

function trimCell(val) {
  return typeof val === "string" ? val.trim() : val;
}

/** 기동 시 스키마·USERS 행 수 확인 (문제일 때만 자세히 출력) */
async function logOracleUsersSanity() {
  let conn;
  try {
    conn = await getConnection();

    const who = await conn.execute(
      "SELECT USER AS u, SYS_CONTEXT('USERENV','CON_NAME') AS pdb FROM DUAL"
    );
    const row0 = who.rows?.[0];
    const schema = Array.isArray(row0) ? row0[0] : row0?.U ?? row0?.USER ?? firstCell(row0);
    const pdb = Array.isArray(row0) ? row0[1] : row0?.PDB ?? row0?.pdb;

    const hasTable = await conn.execute(
      "SELECT COUNT(*) AS c FROM user_tables WHERE table_name = 'USERS'"
    );
    const ownTable = Number(firstCell(hasTable.rows?.[0]));

    const owners = await conn.execute(
      "SELECT DISTINCT owner FROM all_tables WHERE table_name = 'USERS' ORDER BY 1"
    );
    const ownerList = (owners.rows || [])
      .map((r) => (Array.isArray(r) ? r[0] : r.OWNER ?? r.owner))
      .filter(Boolean)
      .join(", ");

    let userCount = 0;
    if (ownTable > 0) {
      const total = await conn.execute("SELECT COUNT(*) AS c FROM users");
      userCount = Number(firstCell(total.rows?.[0]));
    }

    if (userCount > 0 && ownTable > 0) {
      console.log(`[Oracle] ${schema} @ ${pdb ?? "?"} · USERS ${userCount}행`);
      return;
    }

    console.log(
      `[Oracle] ${schema} @ ${pdb ?? "?"} · USERS 테이블: ${ownTable > 0 ? "있음" : "없음"} · 행: ${userCount}`
    );
    if (ownerList) {
      console.log(`[Oracle] USERS 소유 스키마: ${ownerList}`);
    }
    if (ownTable === 0 && ownerList) {
      console.warn(
        "[Oracle] 이 계정에 USERS가 없습니다. 데이터를 넣은 사용자(예: C##cds)로 접속했는지 확인하세요."
      );
    } else if (userCount === 0 && ownTable > 0) {
      console.warn("[Oracle] USERS가 비어 있습니다. sql/seed_data_only.sql 등으로 INSERT 하세요.");
    } else if (userCount === 0) {
      console.warn("[Oracle] ORACLE_USER / ORACLE_CONNECT_STRING 확인 (PowerShell: $env:ORACLE_USER='C##cds')");
    }
  } catch (e) {
    console.warn("[Oracle] 확인 실패:", e.message);
    if (e.errorNum === 1017 || String(e.message).includes("ORA-01017")) {
      console.warn(
        `[Oracle] 시도한 계정: "${oracleConfig.user}" @ ${oracleConfig.connectString} (비번은 ORACLE_PASSWORD)`
      );
      console.warn(
        "[Oracle] 이전에 쓰던 터미널과 다르면 환경 변수가 없어져 기본값(cds/1234)으로 붙습니다. 예: $env:ORACLE_USER='C##cds'; $env:ORACLE_PASSWORD='1234'"
      );
    }
  } finally {
    await closeQuietly(conn);
  }
}

/** OTP 대기: 최초 등록 { kind, secret } · 기존 사용자 true */
const tempUsers = Object.create(null);

app.post("/login", async (req, res) => {
  const { id, pw } = loginCredentials(req);
  if (!id || !pw) {
    return res.status(400).json({ message: "아이디와 비밀번호를 입력해 주세요." });
  }

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `SELECT user_id, password, role, otp_secret FROM users
       WHERE TRIM(user_id) = :id AND TRIM(password) = :pw`,
      { id, pw }
    );
    const row = result.rows[0];
    if (!row) {
      return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
    }

    const otpSecret = row[3];
    if (!otpSecret) {
      const newSecret = speakeasy.generateSecret({
        length: 20,
        name: `CDS:${id}`,
        issuer: "CDS"
      });
      const qr = await QRCode.toDataURL(newSecret.otpauth_url);
      tempUsers[id] = { kind: "setup", secret: newSecret.base32 };
      console.log(`[OTP] setup id=${id}`);
      return res.json({ qr });
    }

    tempUsers[id] = true;
    return res.json({ message: "OTP 필요" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "서버 오류" });
  } finally {
    await closeQuietly(conn);
  }
});

app.post("/verify-otp", async (req, res) => {
  const id = String(req.body?.id ?? "").trim();
  // 인증 앱이 "123 456"처럼 띄어쓰기로 표시하는 경우가 있어 숫자만 남긴다.
  const otp = String(req.body?.otp ?? "").replace(/\D/g, "");
  const pending = tempUsers[id];
  if (!pending) {
    return res.status(401).json({ message: "로그인 필요" });
  }

  const isFirstSetup =
    pending && typeof pending === "object" && pending.kind === "setup" && pending.secret;

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      "SELECT user_id, role, otp_secret FROM users WHERE TRIM(user_id) = :id",
      { id }
    );
    const row = result.rows[0];
    if (!row) {
      return res.status(404).json({ message: "사용자 없음" });
    }

    let userId = trimCell(row[0]);
    let role = trimCell(row[1]);
    const secretInDb = row[2];
    const secretForVerify = isFirstSetup ? pending.secret : secretInDb;

    if (!secretForVerify) {
      return res.status(400).json({
        message: "OTP 설정이 완료되지 않았습니다. DB의 otp_secret을 비우고 다시 로그인하세요."
      });
    }

    const verified = speakeasy.totp.verify({
      secret: secretForVerify,
      encoding: "base32",
      token: otp,
      window: 1
    });
    console.log(`[OTP] verify id=${id} firstSetup=${!!isFirstSetup} ok=${verified}`);
    if (!verified) {
      return res.status(401).json({ message: "OTP 번호가 올바르지 않습니다" });
    }

    if (isFirstSetup) {
      await conn.execute(
        "UPDATE users SET otp_secret = :secret WHERE TRIM(user_id) = :id",
        { secret: pending.secret, id }
      );
      await conn.commit();
    }

    const level = String(role ?? "")
      .trim()
      .toUpperCase()
      .charAt(0);
    if (!["C", "S", "O"].includes(level)) {
      return res.status(500).json({
        message: "사용자 등급(role)이 C/S/O가 아닙니다. Oracle users.role을 확인하세요.",
        role: role
      });
    }
    const token = jwt.sign({ sub: userId, level }, SECRET_KEY, { expiresIn: "1h" });
    delete tempUsers[id];
    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "서버 오류" });
  } finally {
    await closeQuietly(conn);
  }
});

/**
 * CDS API 역프록시 (동일 출처). 브라우저 CORS·CDS 미기동 시에도 502 JSON으로 원인 파악 가능.
 * 예: GET /api/cds/documents/s3-index?page=1 → GET {CDS}/documents/s3-index?page=1
 */
app.use("/api/cds", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "토큰 없음" });
  }
  // Express 버전에 따라 mount 내부 req.url이 달라질 수 있어, 항상 originalUrl 기준으로 CDS 경로만 붙인다.
  const raw = req.originalUrl || req.url || "/";
  const pathOnCds = raw.replace(/^\/api\/cds/, "") || "/";
  const targetUrl =
    CDS_API_URL + (pathOnCds.startsWith("/") ? pathOnCds : `/${pathOnCds}`);
  const init = {
    method: req.method,
    headers: {
      Authorization: authHeader
    },
    redirect: "manual"
  };
  if (req.method !== "GET" && req.method !== "HEAD") {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(req.body ?? {});
  }
  try {
    const upstream = await fetch(targetUrl, init);
    const buf = Buffer.from(await upstream.arrayBuffer());
    const ct = upstream.headers.get("content-type");
    if (ct) {
      res.setHeader("Content-Type", ct);
    }
    res.status(upstream.status).send(buf);
  } catch (err) {
    console.error("[CDS proxy]", targetUrl, err.message);
    return res.status(502).json({
      message: "CDS 서버에 연결할 수 없습니다.",
      detail: String(err.message),
      hint: "CDS를 실행했는지 확인하세요 (예: uvicorn main:app --reload --port 8000). CDS_API_URL=" + CDS_API_URL
    });
  }
});

app.get("/data", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "토큰 없음" });
  }
  const token = authHeader.split(" ")[1];
  let conn;

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const levelRank = { O: 1, S: 2, C: 3 };
    const userLevel = levelRank[decoded.level];

    conn = await getConnection();
    const result = await conn.execute(
      `SELECT doc_id, title, doc_level, file_name, file_path, created_at
       FROM documents
       ORDER BY doc_id`
    );

    const data = (result.rows || []).map((row) => {
      const docLevel = trimCell(row[2]);
      const docRank = levelRank[docLevel];
      let status = "제한";
      if (userLevel >= docRank) {
        status = "열람";
      } else if (docRank - userLevel === 1) {
        status = "요청";
      }
      return {
        doc_id: row[0],
        title: row[1],
        doc_level: row[2],
        created_at: row[5],
        status
      };
    });

    return res.json({ message: "문서 조회 성공", user: decoded, data });
  } catch (err) {
    console.error(err);
    if (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "토큰 유효하지 않음" });
    }
    return res.status(500).json({ message: "서버 오류" });
  } finally {
    await closeQuietly(conn);
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.listen(3000, async () => {
  console.log("http://localhost:3000");
  console.log(`CDS 프록시: /api/cds → ${CDS_API_URL}`);
  console.log(`Oracle: ${oracleConfig.user} @ ${oracleConfig.connectString}`);
  await logOracleUsersSanity();
});
