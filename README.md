# MyScanner (포트 스캔·인벤토리·Triage/Remediation 관리)

MyScanner는 **Nmap 스캔 결과(XML)** 를 인벤토리에 반영하고, 포트 노출에 대한 **Triage(검토/소명) → Remediation(조치/예외)** 흐름을 웹 UI로 관리하는 솔루션입니다.

해당 솔루션은 정기적인 포트스캔을 내/외부자 관점으로 진행할 때, 이력과 포트에 대한 조치사항을 관리 목적으로 사용합니다.

- 주 이용자 : 취약점 담당 인력 & IT 방화벽을 담당하는 인력

- Backend: FastAPI + SQLAlchemy + PostgreSQL
- Frontend: Jinja2 템플릿(서버사이드 렌더링)
- Scan engine: Nmap (XML 출력 기반)
- Security: 서버사이드 세션 + MFA(TOTP) + 임시 비밀번호/강제 변경

---

## 주요 기능

### Dashboard
- 최근 스캔/인벤토리 요약
- Scan Run 목록(실행 로그 확인, Ingest, 삭제)
<img width="1185" height="401" alt="image" src="https://github.com/user-attachments/assets/a83732e9-3d61-4efe-8340-89c2f54f2fd2" />

### Scan Run
- 대상/포트 범위/옵션으로 Nmap 실행
- 방화벽 차단/허용 상태를 통해 스캔 진행 시 방화벽을 허용절차를 거치고 수행했는지(내부망 스캔),- 방화벽 차단을 유지한 상태로 스캔(공격자 관점 스캔)으로 진행하였는지 표기 가능
- 실행 로그 tail/stream 확인
- **스캔 종료 시 `Ingest` 버튼 클릭으로 XML을 Inventory에 반영**
- Ingest 성공(SUCCESS) 후 **스캔 아티팩트(xml/log)를 자동 삭제**(로그 무한 누적 방지)

#### 스캔 실행시
<img width="1163" height="831" alt="image" src="https://github.com/user-attachments/assets/aee5f984-bf11-431a-891f-7947f82e6065" />

#### View Option(스캔완료)
<img width="1170" height="953" alt="image" src="https://github.com/user-attachments/assets/2fb176cb-891d-4b54-95b1-bb40afaec137" />


###  Results
- IP/Port 기준 포트 인벤토리 관리
- FW 프로필(Y/N) 포함 데이터가 존재하더라도 **(IP,Port)는 동일 단위로 상태/미탐 카운트를 동기화**(중복/불일치 방지)
- Excel Export 지원
<img width="1184" height="812" alt="image" src="https://github.com/user-attachments/assets/8f60573b-d0ff-440e-8b8b-21aca6fbefc4" />


### Triage Queue / Remediated
- 상태(Status)와 Reviewed에 따라 데이터가 Triage Queue와 Remediated 메뉴로 자동 분리됩니다.
- **중복입력 방지 정책**
  - FW(방화벽)플래그가 다른 동일 IP/PORT의 경우 데이터가 중첩되어 생길 수 있습니다.(IP/PORT 당 최대 2개 데이터)
  - 동일한 IP/PORT에 대한 내용의 중복적인 기입을 방지하기 위해 이미 동일한 IP/PORT로 기입된 정보가 있으면, 새로 생기는 데이터 또한 동일한 내용이 입력되도록 설계하였습니다.
- **휴먼에러 방지 정책**
  - `REMEDIATED` / `IGNORED`로 바꾸면 **Reviewed가 자동으로 Y 처리**되어 실수로 Reviewed를 안 올려도 “사라짐”이 발생하지 않도록 설계
  - `DENIED`는 Triage Queue에 유지(추가 검토 대상)하며 Reviewed는 강제로 N
  - `REMEDIATED/DENIED/IGNORED → ACTIVE`로 되돌리면 **Reviewed=N으로 초기화**되어 Triage Queue에 다시 표시
- **INACTIVE(미탐 2회) 상태**가 되면 휴먼에러 방지를 위해 **Status/Reviewed 수정이 금지**됩니다.
  - 이후 스캔에서 다시 탐지(open)되면 INACTIVE 해제 + Reviewed 초기화로 Triage로 복귀

<img width="1178" height="662" alt="image" src="https://github.com/user-attachments/assets/5b6a837e-4cbd-47db-a903-8e8fd0f6f164" />

### Asset
- 스캔시, open된 포트를 보유한이력이 있는 IP를 목록으로 관리하는 기능입니다.
<img width="1171" height="395" alt="image" src="https://github.com/user-attachments/assets/e08e6c65-9b10-488c-b515-639bfedad612" />

### Audit(관리자 접근가능)
- 주요 작업(스캔/반영/계정관리/상태변경 등) 감사 로그
- 날짜 필터는 **KST(Asia/Seoul) 기준**으로 동작하도록 UTC 저장 시간을 변환해 조회
<img width="1157" height="798" alt="image" src="https://github.com/user-attachments/assets/4a593401-9aea-433c-bd8e-a9b1f3399503" />


### 계정/보안
- 역할(Role): `admin`, `operator`
  - admin: 스캔 실행/중지/삭제/ingest, 사용자 관리, 감사로그 접근
  - operator: 조회 및 제한된 운영(설정에 따라 조정 가능)
- 비밀번호 정책(회원가입): **8자 이상 + 대문자/소문자/숫자/특수문자 각각 1개 이상**
- MFA(TOTP): google authenticator app 지원,첫 로그인 시 등록 강제 → 이후 로그인 시 항상 코드 요구
- Reset PW: 정책을 만족하는 **랜덤 임시 비밀번호 발급** + `must_change_password=True`
- 임시 비밀번호로 로그인 시 **강제 비밀번호 변경 페이지(/change_password)** 로만 접근 가능
- Reset MFA / Force Logout / Delete user: Users(admin) 메뉴에서 관리

### 관리자 계정 만들기
```
1. operator role 로 웹 회원가입
2. DB에 직접 role 변경
  docker compose exec db psql -U myscanner -d myscanner -c "UPDATE users SET role = 'admin' WHERE user_id = '<id>';"
```


#### admin 화면
<img width="1418" height="713" alt="image" src="https://github.com/user-attachments/assets/23055a48-98ec-4304-9d2b-02ecc90df15c" />

#### operator 화면
<img width="1358" height="717" alt="image" src="https://github.com/user-attachments/assets/dece27db-e19e-4860-bf8a-291457c12c19" />

### Users
<img width="1417" height="387" alt="image" src="https://github.com/user-attachments/assets/bbf756a2-d71b-475a-a885-3d11286bdcc8" />

---

## 실행 방법 (Linux 서버 권장)

### 1) 사전 준비
- Python 3.12+
- PostgreSQL 16+
- Nmap 설치
  - Ubuntu 예: `sudo apt-get update && sudo apt-get install -y nmap`

### 2) 가상환경 실행(권장)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

환경변수(예시):
```bash
export DATABASE_URL="postgresql+psycopg2://myscanner:myscanner@localhost:5432/myscanner"
export LOG_DIR="/var/MyScanner/log"
export ALLOWED_TARGETS="192.168.0.0/16,10.0.0.0/8"
export DEFAULT_TCP_ARGS="-sT -sV -Pn -T3 -vv"
export TZ="Asia/Seoul"
```

로그 디렉터리:
```bash
sudo mkdir -p /var/MyScanner/log
sudo chown -R $(whoami):$(whoami) /var/MyScanner/log
```

서버 실행:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## Docker로 실행(선택)

> 저장소의 `docker-compose.yml`은 환경에 따라 수정이 필요할 수 있습니다(경로/볼륨/로그 디렉터리).
> 아래는 가장 일반적인 예시입니다.

- Postgres는 `pgdata` 볼륨 사용
- 앱은 `LOG_DIR`을 컨테이너/호스트에 마운트

```yaml
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_DB: myscanner
      POSTGRES_USER: myscanner
      POSTGRES_PASSWORD: myscanner
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U myscanner -d myscanner"]
      interval: 3s
      timeout: 3s
      retries: 30

  web:
    build: .
    environment:
      DATABASE_URL: postgresql+psycopg2://myscanner:myscanner@db:5432/myscanner
      SESSION_SECRET: "change-me-in-prod"
      LOG_DIR: "/var/MyScanner/log"
      ALLOWED_TARGETS: "192.168.0.0/16,10.0.0.0/8"
      DEFAULT_NMAP_ARGS: "-sT -sV -Pn -T3 -vv"
      TZ: "Asia/Seoul"
    volumes:
      - /var/MyScanner/log:/var/MyScanner/log
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "8000:8000"

volumes:
  pgdata:

```

---

## 운영 팁

### Reverse Proxy + HTTPS
운영 환경에서는 Nginx(또는 Caddy) 뒤에 두고 HTTPS를 권장합니다.

### 스캔 아티팩트(xml/log) 보관 정책
Ingest 성공 후 xml/log를 자동 삭제하도록 되어 있어 디스크 누수를 방지합니다.
감사/분석 목적으로 보관이 필요하면 해당 정책을 변경하거나, 별도 아카이빙(압축/보관 디렉터리 이동)을 권장합니다.

### 데이터 백업
- PostgreSQL: `pg_dump` 또는 볼륨 스냅샷
- 로그/아티팩트: 필요 시만 백업(운영 정책에 따라)

---

## License
(사용자가 추가) MIT © 2025 AndrewAhn
