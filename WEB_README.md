# OSINT Collection Tool - 웹 인터페이스

브라우저에서 OSINT 도구를 사용할 수 있는 웹 기반 인터페이스입니다.

## 주요 기능

### 🌐 웹 기반 인터페이스
- **직관적인 UI**: 사용하기 쉬운 웹 인터페이스
- **실시간 진행 상황**: 스캔 진행률 및 로그 실시간 표시
- **모듈 선택**: 원하는 OSINT 모듈만 선택하여 실행
- **결과 시각화**: 수집된 정보를 보기 좋게 표시
- **다중 출력 형식**: JSON, HTML 형식으로 다운로드

### 📊 기능
- DNS 정보 수집
- WHOIS 조회
- 서브도메인 열거
- 포트 스캔
- 웹 기술 스택 분석
- 외부 API 통합 (설정 시)

## 빠른 시작

### 1. 설치

```bash
# 의존성 설치
pip install -r requirements.txt
```

### 2. 실행

```bash
# 웹 서버 시작
python web_app.py
```

### 3. 접속

브라우저에서 다음 주소로 접속:
```
http://localhost:5000
```

## 사용 방법

### 1. 새 스캔 시작

1. 메인 페이지에서 대상 도메인 또는 IP 입력
2. 실행할 OSINT 모듈 선택
3. "스캔 시작" 버튼 클릭

### 2. 진행 상황 모니터링

- 실시간 진행률 표시
- 로그 창에서 세부 진행 사항 확인
- 각 모듈의 실행 상태 확인

### 3. 결과 확인

스캔 완료 후:
- "결과 보기" 버튼으로 상세 결과 페이지 이동
- JSON 또는 HTML 형식으로 다운로드
- 웹 페이지에서 직접 결과 확인

## 웹 인터페이스 구조

```
web/
├── templates/          # HTML 템플릿
│   ├── index.html     # 메인 페이지
│   └── results.html   # 결과 페이지
└── static/            # 정적 파일
    ├── css/
    │   └── style.css  # 스타일시트
    └── js/
        ├── main.js    # 메인 페이지 로직
        └── results.js # 결과 페이지 로직
```

## API 엔드포인트

### POST /api/scan/start
새 스캔 시작

**요청:**
```json
{
  "target": "example.com",
  "dns_enumeration": true,
  "whois_lookup": true,
  "subdomain_enumeration": true,
  "port_scanning": true,
  "web_technology_detection": true
}
```

**응답:**
```json
{
  "scan_id": "uuid",
  "message": "Scan started successfully"
}
```

### GET /api/scan/{scan_id}/status
스캔 상태 조회

**응답:**
```json
{
  "id": "uuid",
  "target": "example.com",
  "status": "running",
  "progress": 45,
  "logs": [...],
  "created_at": "2024-01-01T12:00:00"
}
```

### GET /api/scan/{scan_id}/results
스캔 결과 조회

**응답:**
```json
{
  "scan_id": "uuid",
  "target": "example.com",
  "results": {
    "dns": {...},
    "whois": {...},
    "subdomains": {...},
    "ports": {...},
    "web": {...}
  }
}
```

### GET /api/scan/{scan_id}/download/{format}
결과 다운로드 (format: json, html)

### GET /api/scans
모든 스캔 목록 조회

### DELETE /api/scan/{scan_id}
스캔 삭제

## 설정

### 포트 변경

`web_app.py` 파일에서 포트 번호 수정:

```python
app.run(host='0.0.0.0', port=5000, debug=True)
```

### 외부 접속 허용

기본적으로 `0.0.0.0`으로 설정되어 있어 외부 접속이 가능합니다.

**보안 경고**: 프로덕션 환경에서는 적절한 인증 및 보안 설정이 필요합니다!

### OSINT 모듈 설정

`osint_tool/configs/config.yaml` 파일에서 모듈 및 API 설정:

```yaml
modules:
  dns_enumeration: true
  whois_lookup: true
  subdomain_enumeration: true
  port_scanning: true
  web_technology_detection: true

external_apis:
  enabled: true
  shodan:
    enabled: false
    api_key: "YOUR_KEY"
```

## 기능 설명

### 실시간 로그

스캔 진행 중 실시간으로 로그가 표시됩니다:
- 🔵 **정보**: 일반 정보
- 🟢 **성공**: 성공한 작업
- 🟡 **경고**: 경고 메시지
- 🔴 **오류**: 오류 발생
- 🟣 **디버그**: 디버그 정보

### 진행률 표시

- 전체 진행률을 백분율로 표시
- 프로그레스 바로 시각적 표현
- 각 모듈별 진행 상황 로그로 확인

### 결과 시각화

#### DNS 정보
- DNS 레코드 (A, AAAA, MX, NS, TXT 등)
- 네임서버 목록
- MX 레코드 우선순위

#### WHOIS 정보
- 도메인 등록 정보
- 등록자 정보
- 도메인 나이 및 만료일

#### 서브도메인
- 발견된 모든 서브도메인
- 각 서브도메인의 IP 주소
- 발견 출처

#### 포트 스캔
- 오픈 포트 목록
- 서비스 탐지 결과
- 배너 정보

#### 웹 분석
- 웹 서버 및 기술 스택
- SSL/TLS 인증서 정보
- 메타데이터
- 발견된 이메일 주소

## 프로덕션 배포

### Gunicorn 사용

```bash
# Gunicorn 설치
pip install gunicorn

# 실행
gunicorn -w 4 -b 0.0.0.0:5000 web_app:app
```

### Nginx 리버스 프록시

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 환경 변수

```bash
# 프로덕션 모드
export FLASK_ENV=production

# 디버그 비활성화
export FLASK_DEBUG=0
```

## 보안 고려사항

### ⚠️ 중요 보안 경고

1. **인증 추가 필요**
   - 현재 버전은 인증이 없습니다
   - 프로덕션에서는 반드시 인증 추가

2. **HTTPS 사용**
   - SSL/TLS 인증서 설정 필요
   - Let's Encrypt 무료 인증서 사용 권장

3. **방화벽 설정**
   - 필요한 포트만 개방
   - IP 화이트리스트 고려

4. **속도 제한**
   - API 요청 속도 제한 구현
   - DDoS 방어 설정

5. **입력 검증**
   - 현재 기본적인 검증만 구현
   - 추가적인 입력 검증 권장

## 문제 해결

### 포트가 이미 사용 중

```bash
# 다른 포트 사용
python web_app.py  # web_app.py에서 포트 변경

# 또는 환경 변수 사용
export FLASK_RUN_PORT=8000
flask run
```

### 스캔이 시작되지 않음

1. 로그 확인
2. 타겟 형식 확인 (올바른 도메인/IP)
3. 네트워크 연결 확인
4. 방화벽 설정 확인

### 결과가 표시되지 않음

1. 브라우저 콘솔에서 에러 확인 (F12)
2. 서버 로그 확인
3. API 응답 확인

## 개발 모드

### 자동 재시작

Flask는 코드 변경 시 자동으로 재시작됩니다 (debug=True).

### 디버깅

```python
# web_app.py에서
app.run(debug=True)  # 이미 설정됨
```

## 성능 최적화

### 동시 스캔 수 제한

현재는 메모리 내 딕셔너리로 스캔 관리. 프로덕션에서는:
- Redis 사용 권장
- 데이터베이스 사용 고려
- 작업 큐 (Celery) 사용

### 캐싱

- 결과 캐싱 구현
- 정적 파일 캐싱 설정

## 기여

버그 리포트 및 기능 제안은 이슈로 등록해주세요.

## 라이선스

교육 및 승인된 보안 테스트 목적으로만 사용하세요.

---

**면책 조항**: 이 도구는 교육 및 승인된 보안 테스트 목적으로만 제공됩니다. 사용자는 적용 가능한 모든 법률과 규정을 준수할 책임이 있습니다.
