# 사용 예시 가이드

## 기본 사용법

### 1. 간단한 도메인 조사
```bash
python osint_tool.py -t example.com
```

**수집되는 정보:**
- DNS 레코드 (A, AAAA, MX, NS, TXT, CNAME, SOA)
- WHOIS 정보
- 서브도메인 목록
- 오픈 포트
- 웹 기술 스택

**출력:**
- `reports/example.com_20240101_120000.json`
- `reports/example.com_20240101_120000.html`

### 2. IP 주소 조사
```bash
python osint_tool.py -t 8.8.8.8
```

**수집되는 정보:**
- 역방향 DNS
- 오픈 포트
- IP 지오로케이션
- (Shodan API 활성화 시) 취약점 정보

## 시나리오별 사용법

### 시나리오 1: 빠른 정찰 (Reconnaissance)
```bash
# 웹 정보만 빠르게 수집
python osint_tool.py -t target.com --no-ports -q
```

**사용 상황:**
- 시간이 제한적일 때
- 네트워크 스캔 없이 공개 정보만 수집
- 소극적(passive) OSINT만 필요한 경우

### 시나리오 2: 서브도메인 중점 조사
```bash
# config.yaml에서 서브도메인 모듈만 활성화
python osint_tool.py -t target.com
```

**설정:**
```yaml
modules:
  dns_enumeration: true
  subdomain_enumeration: true
  # 나머지는 false
```

### 시나리오 3: 완전한 포트 스캔
```bash
python osint_tool.py -t target.com --all
```

**config.yaml 수정:**
```yaml
limits:
  port_range: "1-65535"  # 모든 포트
  max_ports: 65535
```

### 시나리오 4: 웹 애플리케이션 분석
```bash
python osint_tool.py -t https://target.com --no-ports
```

**수집되는 정보:**
- HTTP 헤더
- SSL/TLS 인증서
- 웹 기술 (서버, 프레임워크, CMS)
- JavaScript 라이브러리
- 이메일 주소
- 소셜 미디어 링크

### 시나리오 5: API 활용 심화 조사
```bash
python osint_tool.py -t target.com -v
```

**사전 설정 (config.yaml):**
```yaml
external_apis:
  enabled: true

  shodan:
    enabled: true
    api_key: "YOUR_SHODAN_KEY"

  virustotal:
    enabled: true
    api_key: "YOUR_VT_KEY"

  securitytrails:
    enabled: true
    api_key: "YOUR_ST_KEY"
```

**추가 수집 정보:**
- Shodan에서 발견된 취약점
- VirusTotal 평판 점수
- SecurityTrails DNS 히스토리
- 이전 IP 주소 기록

## 고급 사용법

### 커스텀 워드리스트 사용
```yaml
# config.yaml
subdomain_wordlist:
  use_builtin: false
  custom_wordlist: "/path/to/wordlist.txt"
```

```bash
python osint_tool.py -t target.com
```

### 프록시 사용
```yaml
# config.yaml
proxy:
  enabled: true
  http: "http://proxy:8080"
  https: "https://proxy:8080"
```

### 속도 제한 조정
```yaml
# config.yaml
rate_limiting:
  enabled: true
  requests_per_second: 2  # 느리게
  delay_between_requests: 0.5
```

### 특정 포트만 스캔
```yaml
# config.yaml
limits:
  common_ports: [80, 443, 8080, 8443]
```

## 출력 형식별 사용

### JSON 출력 (자동화/프로그래밍)
```bash
python osint_tool.py -t target.com -o json

# jq로 파싱
cat reports/target.com_*.json | jq '.dns.nameservers'
```

### HTML 출력 (보고서)
```bash
python osint_tool.py -t target.com -o html

# 브라우저로 열기
firefox reports/target.com_*.html
```

### 텍스트 출력 (빠른 확인)
```bash
python osint_tool.py -t target.com -o txt

# 터미널에서 보기
less reports/target.com_*.txt
```

### 모든 형식 출력
```bash
python osint_tool.py -t target.com -o json html txt
```

## 실전 워크플로우

### 워크플로우 1: 블랙박스 펜테스트 초기 정찰
```bash
# 1단계: 기본 정보 수집
python osint_tool.py -t target.com -o json html

# 2단계: 결과 분석
cat reports/target.com_*.json | jq '.subdomains.subdomains[] | .subdomain'

# 3단계: 발견된 서브도메인별 조사
python osint_tool.py -t subdomain.target.com --no-web

# 4단계: 오픈 포트가 있는 호스트 상세 조사
python osint_tool.py -t 192.168.1.100
```

### 워크플로우 2: 도메인 자산 인벤토리
```bash
# domains.txt 파일 생성
echo "domain1.com" > domains.txt
echo "domain2.com" >> domains.txt
echo "domain3.com" >> domains.txt

# 배치 처리
while read domain; do
  python osint_tool.py -t "$domain" -o json
  sleep 5
done < domains.txt

# 결과 통합
cat reports/*.json > all_results.json
```

### 워크플로우 3: 취약점 평가 사전 조사
```bash
# 1. 서브도메인 발견
python osint_tool.py -t target.com --no-ports --no-web -o json

# 2. 발견된 서브도메인 추출
cat reports/target.com_*.json | jq -r '.subdomains.subdomains[] | .subdomain' > subdomains.txt

# 3. 각 서브도메인의 웹 기술 스택 분석
while read subdomain; do
  python osint_tool.py -t "$subdomain" --no-ports -o json
done < subdomains.txt

# 4. 취약한 기술 스택 검색
# (예: 오래된 WordPress, 취약한 플러그인 등)
```

## 모의해킹 단계별 활용

### Phase 1: Information Gathering (정보 수집)
```bash
# 수동(Passive) OSINT
python osint_tool.py -t target.com --no-ports -q

# 능동(Active) OSINT
python osint_tool.py -t target.com
```

### Phase 2: Scanning & Enumeration (스캔 및 열거)
```bash
# 포트 스캔 중점
python osint_tool.py -t target.com --all

# 서비스 버전 탐지
# (결과의 banner 필드 확인)
```

### Phase 3: Vulnerability Assessment (취약점 평가)
```bash
# API 활용 취약점 정보 수집
python osint_tool.py -t target.com -v

# Shodan 결과에서 CVE 확인
cat reports/target.com_*.json | jq '.api.shodan.vulns'
```

## 팁과 트릭

### 1. 시간 절약하기
```bash
# 빠른 스캔 설정
python osint_tool.py -t target.com --no-ports --no-web -q
```

### 2. 상세한 로그 보기
```bash
# 상세 모드
python osint_tool.py -t target.com -v 2>&1 | tee scan.log
```

### 3. 실패한 스캔 재시도
```bash
# 타임아웃 증가
# config.yaml에서 timeout: 60
python osint_tool.py -t slow-target.com
```

### 4. 결과 비교
```bash
# 첫 번째 스캔
python osint_tool.py -t target.com -o json
mv reports/target.com_*.json scan1.json

# 나중에 다시 스캔
python osint_tool.py -t target.com -o json
mv reports/target.com_*.json scan2.json

# 차이 확인
diff <(jq -S . scan1.json) <(jq -S . scan2.json)
```

### 5. 특정 모듈만 실행
```bash
# config.yaml에서 원하는 모듈만 true로 설정
# 예: DNS만
modules:
  dns_enumeration: true
  whois_lookup: false
  subdomain_enumeration: false
  # ...
```

## 주의사항

### 법적 고려사항
- 항상 테스트 권한을 먼저 확보하세요
- 자신이 소유하지 않은 시스템은 스캔하지 마세요
- 해당 지역의 법률을 준수하세요

### 속도 제한
- 외부 API는 속도 제한이 있습니다
- 너무 빠른 스캔은 차단될 수 있습니다
- `rate_limiting` 설정을 활용하세요

### 네트워크 고려사항
- 포트 스캔은 네트워크 트래픽을 생성합니다
- IDS/IPS가 탐지할 수 있습니다
- 테스트 환경에서 먼저 실행하세요

## 문제 해결

### "Connection timeout" 오류
```bash
# 타임아웃 증가
# config.yaml: timeout: 60
```

### "API key invalid" 오류
```bash
# API 키 재확인
# config.yaml에서 올바른 키 입력 확인
```

### "Permission denied" 오류
```bash
# Linux에서 1024 이하 포트 스캔 시
sudo python osint_tool.py -t target.com
```

### DNS 해석 실패
```bash
# 다른 DNS 서버 사용
# config.yaml:
dns:
  nameservers:
    - "1.1.1.1"  # Cloudflare
    - "9.9.9.9"  # Quad9
```
