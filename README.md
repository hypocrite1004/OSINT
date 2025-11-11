# OSINT Collection Tool

종합 OSINT (Open Source Intelligence) 자동화 도구입니다. 모의해킹 블랙박스 테스트 시 기본 정보만으로 최대한의 정보를 수집하도록 설계되었습니다.

## 주요 기능

### 핵심 모듈
- **DNS 정보 수집**: DNS 레코드, 네임서버, MX 레코드, TXT 레코드, SOA 레코드
- **WHOIS 조회**: 도메인 등록 정보, 등록자 정보, 만료일 등
- **서브도메인 열거**: 브루트포스, Certificate Transparency 로그, 외부 API 활용
- **포트 스캔**: 일반 포트, 포트 범위, 서비스 탐지, 배너 그래빙
- **웹 기술 스택 분석**: 웹 서버, 프레임워크, CMS, JavaScript 라이브러리 탐지
- **SSL/TLS 인증서 분석**: 인증서 정보, SAN, 발급자, 유효기간
- **연락처 정보 추출**: 이메일 주소, 전화번호, 소셜 미디어 링크
- **IP 지오로케이션**: IP 주소의 위치 정보, ISP, ASN

### 외부 API 통합
- **Shodan**: 호스트 정보, 오픈 포트, 취약점 정보
- **VirusTotal**: 도메인/IP 평판, 악성코드 탐지 이력
- **SecurityTrails**: 서브도메인 정보, DNS 히스토리
- **HaveIBeenPwned**: 이메일 유출 여부 확인
- **URLScan.io**: URL 스캔 및 분석
- **IPInfo.io**: IP 지오로케이션 및 상세 정보

## 설치

### 요구사항
- Python 3.7 이상
- pip (Python 패키지 관리자)

### 설치 방법

```bash
# 저장소 클론
git clone <repository-url>
cd OSINT

# 의존성 설치
pip install -r requirements.txt

# 실행 권한 부여 (Linux/Mac)
chmod +x osint_tool.py
```

## 설정

`osint_tool/configs/config.yaml` 파일을 수정하여 도구 동작을 설정할 수 있습니다.

### 주요 설정 항목

#### 1. 모듈 활성화/비활성화
```yaml
modules:
  dns_enumeration: true
  whois_lookup: true
  subdomain_enumeration: true
  port_scanning: true
  web_technology_detection: true
  # ... 기타 모듈
```

#### 2. 오픈소스 도구 설정
```yaml
opensource_tools:
  enabled: true  # 전체 활성화/비활성화
  sublist3r: false
  amass: false
  nmap: false
  # ... 기타 도구
```

#### 3. 외부 API 설정
```yaml
external_apis:
  enabled: true  # 전체 활성화/비활성화

  shodan:
    enabled: false
    api_key: "YOUR_API_KEY_HERE"

  virustotal:
    enabled: false
    api_key: "YOUR_API_KEY_HERE"

  # ... 기타 API
```

#### 4. 스캔 제한 설정
```yaml
limits:
  max_subdomains: 1000
  max_ports: 1000
  port_range: "1-1000"
  common_ports: [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]
```

#### 5. 출력 설정
```yaml
output:
  directory: "./reports"
  timestamp: true
  formats:
    - json
    - html
    - txt
```

## 사용법

### 기본 사용

```bash
# 기본 스캔
python osint_tool.py -t example.com

# 모든 모듈 실행
python osint_tool.py -t example.com --all

# 특정 출력 형식 지정
python osint_tool.py -t example.com -o json html
```

### 고급 옵션

```bash
# 포트 스캔 제외
python osint_tool.py -t example.com --no-ports

# 웹 분석 제외
python osint_tool.py -t example.com --no-web

# 커스텀 설정 파일 사용
python osint_tool.py -t example.com -c custom_config.yaml

# 자세한 출력
python osint_tool.py -t example.com -v

# 최소 출력 (조용한 모드)
python osint_tool.py -t example.com -q
```

### 명령행 옵션

```
필수 인자:
  -t, --target TARGET        대상 도메인 또는 IP 주소

선택 인자:
  -c, --config CONFIG        설정 파일 경로
  -o, --output FORMAT [...]  출력 형식 (json, html, txt)
  --all                      모든 모듈 활성화
  --no-ports                 포트 스캔 건너뛰기
  --no-web                   웹 분석 건너뛰기
  -v, --verbose              자세한 출력
  -q, --quiet                최소 출력 모드
  -h, --help                 도움말 표시
```

## 출력 형식

### JSON
구조화된 데이터 형식으로 프로그래밍 방식으로 처리하기 적합합니다.

```json
{
  "dns": {
    "dns_records": {...},
    "nameservers": [...]
  },
  "whois": {...},
  "subdomains": {...},
  ...
}
```

### HTML
시각적으로 보기 좋은 웹 페이지 형식의 보고서입니다.
- 색상 코딩된 섹션
- 표 형식의 데이터
- 인터랙티브한 레이아웃

### TXT
간단한 텍스트 형식의 보고서입니다.

## 프로젝트 구조

```
OSINT/
├── osint_tool.py                 # 메인 실행 스크립트
├── requirements.txt              # Python 의존성
├── README.md                     # 문서 (이 파일)
├── osint_tool/
│   ├── __init__.py
│   ├── configs/
│   │   └── config.yaml          # 설정 파일
│   ├── modules/                 # OSINT 수집 모듈
│   │   ├── __init__.py
│   │   ├── dns_recon.py         # DNS 정보 수집
│   │   ├── whois_lookup.py      # WHOIS 조회
│   │   ├── subdomain_enum.py    # 서브도메인 열거
│   │   ├── port_scanner.py      # 포트 스캔
│   │   ├── web_analyzer.py      # 웹 분석
│   │   └── api_integrations.py  # 외부 API 통합
│   ├── utils/                   # 유틸리티 모듈
│   │   ├── __init__.py
│   │   ├── config_loader.py     # 설정 로더
│   │   ├── logger.py            # 로깅 유틸리티
│   │   ├── helpers.py           # 헬퍼 함수
│   │   └── report_generator.py  # 보고서 생성
│   └── reports/                 # 생성된 보고서 저장 디렉토리
```

## API 키 설정

일부 기능을 사용하려면 외부 API 키가 필요합니다.

### Shodan API
1. https://account.shodan.io/ 에서 계정 생성
2. API 키 복사
3. `config.yaml`의 `external_apis.shodan.api_key`에 입력

### VirusTotal API
1. https://www.virustotal.com/ 에서 계정 생성
2. API 키 획득
3. `config.yaml`의 `external_apis.virustotal.api_key`에 입력

### SecurityTrails API
1. https://securitytrails.com/ 에서 계정 생성
2. API 키 획득
3. `config.yaml`의 `external_apis.securitytrails.api_key`에 입력

### 기타 API
- **Hunter.io**: 이메일 검색 API
- **HaveIBeenPwned**: 데이터 유출 확인 API
- **URLScan.io**: URL 스캔 API
- **IPInfo.io**: IP 정보 API (API 키 선택사항)

## 사용 예시

### 예시 1: 기본 도메인 정보 수집
```bash
python osint_tool.py -t example.com
```

이 명령은 다음 정보를 수집합니다:
- DNS 레코드
- WHOIS 정보
- 서브도메인
- 오픈 포트
- 웹 기술 스택

### 예시 2: 빠른 정보 수집 (포트 스캔 제외)
```bash
python osint_tool.py -t example.com --no-ports -q
```

### 예시 3: 완전한 정보 수집 (모든 모듈)
```bash
python osint_tool.py -t example.com --all -v -o json html txt
```

### 예시 4: API를 사용한 심화 조사
1. `config.yaml`에서 API 키 설정
2. API 활성화:
```yaml
external_apis:
  enabled: true
  shodan:
    enabled: true
    api_key: "YOUR_SHODAN_API_KEY"
  virustotal:
    enabled: true
    api_key: "YOUR_VT_API_KEY"
```
3. 실행:
```bash
python osint_tool.py -t example.com
```

## 보안 및 윤리적 사용

⚠️ **중요 고지사항**

이 도구는 다음 용도로만 사용해야 합니다:
- 승인된 모의해킹 테스트
- 자신이 소유하거나 테스트 권한이 있는 시스템
- 교육 및 연구 목적
- 보안 연구 및 방어적 보안

**금지 사항:**
- 무단 시스템 침입
- 승인 없는 정보 수집
- 악의적인 목적의 사용
- 법률 위반 행위

사용자는 해당 지역의 법률을 준수할 책임이 있습니다.

## 성능 최적화

### 스레드 수 조정
```yaml
general:
  max_threads: 10  # CPU 코어 수에 맞게 조정
```

### 타임아웃 설정
```yaml
general:
  timeout: 30  # 네트워크 속도에 맞게 조정
```

### 속도 제한
```yaml
rate_limiting:
  enabled: true
  requests_per_second: 5
  delay_between_requests: 0.2
```

## 문제 해결

### SSL 인증서 오류
SSL 검증 오류가 발생하면 자동으로 검증 없이 재시도합니다.

### DNS 해석 실패
- 네임서버 설정 확인
- 인터넷 연결 확인
- 방화벽 설정 확인

### API 속도 제한
- 무료 API는 속도 제한이 있습니다
- 유료 플랜으로 업그레이드 고려
- `rate_limiting` 설정 조정

### 포트 스캔 권한
일부 시스템에서는 포트 스캔에 관리자 권한이 필요할 수 있습니다.

## 라이선스

이 도구는 교육 및 승인된 보안 테스트 목적으로만 사용하세요.

## 기여

버그 리포트, 기능 제안, 풀 리퀘스트를 환영합니다.

## 업데이트 계획

- [ ] 추가 OSINT 소스 통합
- [ ] 기계 학습 기반 위협 분석
- [ ] 실시간 모니터링 기능
- [ ] 웹 UI 인터페이스
- [ ] Docker 컨테이너 지원
- [ ] API 서버 모드

## 연락처

문제가 발생하거나 질문이 있으면 이슈를 등록해주세요.

---

**면책 조항**: 이 도구는 교육 및 승인된 보안 테스트 목적으로만 제공됩니다. 사용자는 적용 가능한 모든 법률과 규정을 준수할 책임이 있습니다.
