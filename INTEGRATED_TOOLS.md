# 통합 외부 OSINT 도구 가이드

OSINT Collection Tool에 통합된 외부 오픈소스 도구들의 설치 및 사용 가이드입니다.

## 🎯 통합된 도구 목록

### 1. **theHarvester** - 이메일 및 서브도메인 수집
### 2. **OWASP Amass** - 고급 서브도메인 열거
### 3. **Photon** - 웹 크롤러 및 정보 추출
### 4. **Sherlock** - 소셜 미디어 계정 검색

## 📦 설치 방법

### 빠른 설치 (권장)

```bash
# Python 패키지 설치
pip install theHarvester photon-python sherlock-project

# Amass 설치 (Linux)
# Ubuntu/Debian:
sudo apt update
sudo apt install amass

# macOS:
brew install amass

# 또는 바이너리 다운로드:
# https://github.com/OWASP/Amass/releases
```

### 개별 도구 설치

#### theHarvester

```bash
# pip로 설치
pip install theHarvester

# 또는 소스에서 설치
git clone https://github.com/laramies/theHarvester
cd theHarvester
pip install -r requirements.txt
python setup.py install

# 설치 확인
theHarvester -h
```

**기능:**
- 이메일 주소 수집
- 서브도메인 발견
- 호스트명 열거
- IP 주소 수집
- LinkedIn에서 직원 정보 수집

**데이터 소스:**
- Google, Bing, DuckDuckGo
- Shodan, Hunter.io
- LinkedIn, Twitter
- 기타 35+ 소스

#### OWASP Amass

```bash
# Ubuntu/Debian
sudo apt install amass

# macOS
brew install amass

# Windows (Chocolatey)
choco install amass

# Go로 빌드
go install -v github.com/OWASP/Amass/v3/...@master

# 설치 확인
amass -version
```

**기능:**
- 가장 포괄적인 서브도메인 발견
- DNS 열거 및 매핑
- 공격 표면 분석
- 네트워크 매핑

**특징:**
- 100+ 데이터 소스
- 능동/수동 모드
- API 통합 (많은 서비스 지원)

#### Photon

```bash
# pip로 설치
pip install photon-python

# 또는 소스에서
git clone https://github.com/s0md3v/Photon
cd Photon
pip install -r requirements.txt

# 설치 확인
python -c "import photon; print('Photon installed')"
```

**기능:**
- 빠른 웹 크롤링
- URL 추출
- 이메일 및 소셜 미디어 링크 추출
- JavaScript 파일 수집
- 파일 다운로드

**특징:**
- 멀티스레딩
- 사용자 정의 깊이
- 정규표현식 필터링

#### Sherlock

```bash
# pip로 설치
pip install sherlock-project

# 또는 소스에서
git clone https://github.com/sherlock-project/sherlock
cd sherlock
pip install -r requirements.txt

# 설치 확인
sherlock --help
```

**기능:**
- 300+ 소셜 네트워크에서 사용자명 검색
- 빠른 검색 속도
- JSON 출력 지원

**지원 플랫폼:**
- Facebook, Twitter, Instagram
- GitHub, Reddit, Medium
- LinkedIn, YouTube
- 기타 300+ 플랫폼

## ⚙️ 설정

### config.yaml 설정

```yaml
integrated_tools:
  enabled: true  # 전체 활성화

  theharvester:
    enabled: false  # 도구 설치 시 자동 활성화됨
    data_source: "all"  # 데이터 소스 선택
    timeout: 300

  amass:
    enabled: false
    passive: true  # 수동 모드 (권장)
    timeout: 600

  photon:
    enabled: false
    depth: 2  # 크롤링 깊이
    timeout: 300

  sherlock:
    enabled: false
    timeout: 300
    username: ""  # 기본 사용자명
```

## 🚀 사용 방법

### CLI에서 사용

```bash
# 기본 스캔 (통합 도구 자동 실행)
python osint_tool.py -t example.com

# 모든 설치된 도구 실행
python osint_tool.py -t example.com --all
```

### Python 코드에서 사용

```python
from osint_tool.modules.integrated_tools import IntegratedTools
from osint_tool.utils.config_loader import ConfigLoader

# 설정 로드
config = ConfigLoader()

# 통합 도구 초기화
tools = IntegratedTools(config)

# 설치된 도구 확인
print(f"Available tools: {tools.tools_available}")

# theHarvester 실행
results = tools.run_theharvester("example.com")
print(f"Emails: {results['emails']}")
print(f"Hosts: {results['hosts']}")

# Amass 실행
results = tools.run_amass("example.com")
print(f"Subdomains: {results['subdomains']}")

# Photon 실행
results = tools.run_photon("https://example.com")
print(f"URLs: {results['urls']}")

# Sherlock 실행
results = tools.run_sherlock("john_doe")
print(f"Accounts: {results['accounts']}")

# 모든 도구 실행
results = tools.run_all_available("example.com", username="john_doe")
```

### 웹 인터페이스에서 사용

웹 인터페이스를 통해 통합 도구를 선택적으로 실행할 수 있습니다 (향후 업데이트 예정).

## 📊 출력 형식

### theHarvester 결과

```json
{
  "emails": [
    "admin@example.com",
    "contact@example.com"
  ],
  "hosts": [
    "mail.example.com",
    "www.example.com"
  ],
  "ips": [
    "93.184.216.34"
  ]
}
```

### Amass 결과

```json
{
  "subdomains": [
    "www.example.com",
    "mail.example.com",
    "api.example.com"
  ],
  "count": 3
}
```

### Photon 결과

```json
{
  "urls": ["https://external.com"],
  "internal_urls": ["https://example.com/page"],
  "files": ["https://example.com/file.pdf"],
  "scripts": ["https://example.com/app.js"]
}
```

### Sherlock 결과

```json
{
  "username": "john_doe",
  "accounts": [
    {
      "platform": "GitHub",
      "url": "https://github.com/john_doe",
      "exists": true
    },
    {
      "platform": "Twitter",
      "url": "https://twitter.com/john_doe",
      "exists": true
    }
  ],
  "count": 2
}
```

## 💡 사용 팁

### theHarvester

```bash
# 특정 데이터 소스만 사용
# config.yaml에서 data_source 변경
data_source: "google,bing"

# 더 빠른 스캔
data_source: "google"

# API 키가 있는 경우
data_source: "hunter"  # Hunter.io API 키 필요
```

### Amass

```bash
# 수동 모드 (빠르고 조용함)
passive: true

# 능동 모드 (더 많은 결과, 느림)
passive: false

# 타임아웃 조정
timeout: 1200  # 20분
```

### Photon

```bash
# 깊이 조정
depth: 1  # 빠름, 적은 결과
depth: 3  # 느림, 많은 결과

# 특정 파일 타입 수집
# Photon은 자동으로 PDF, DOCX 등 수집
```

### Sherlock

```bash
# 여러 사용자명 검색
# 반복문으로 실행
for username in ["user1", "user2", "user3"]:
    results = tools.run_sherlock(username)
```

## 🔧 문제 해결

### theHarvester가 작동하지 않음

```bash
# 재설치
pip uninstall theHarvester
pip install theHarvester

# 또는 최신 버전
pip install git+https://github.com/laramies/theHarvester
```

### Amass 설치 오류

```bash
# Go가 설치되어 있는지 확인
go version

# PATH 설정 확인
echo $GOPATH
export PATH=$PATH:$GOPATH/bin
```

### Photon ImportError

```bash
# 의존성 재설치
pip install --upgrade photon-python requests

# 또는 소스에서 설치
git clone https://github.com/s0md3v/Photon
cd Photon
pip install -r requirements.txt
```

### Sherlock 속도 제한

```bash
# 타임아웃 증가
timeout: 600

# 또는 특정 플랫폼만 검색
# Sherlock CLI에서: --site GitHub Twitter
```

## 📈 성능 최적화

### 병렬 실행

```python
# 여러 도구를 동시에 실행
import concurrent.futures

tools = IntegratedTools(config)

with concurrent.futures.ThreadPoolExecutor() as executor:
    futures = {
        executor.submit(tools.run_theharvester, "example.com"): "theHarvester",
        executor.submit(tools.run_amass, "example.com"): "Amass"
    }

    for future in concurrent.futures.as_completed(futures):
        tool_name = futures[future]
        result = future.result()
        print(f"{tool_name}: {result}")
```

### 타임아웃 조정

```yaml
# 빠른 스캔 (5분)
integrated_tools:
  theharvester:
    timeout: 300
  amass:
    timeout: 300

# 완전한 스캔 (30분)
integrated_tools:
  theharvester:
    timeout: 1800
  amass:
    timeout: 1800
```

## 🔒 보안 고려사항

1. **속도 제한 준수**: 일부 데이터 소스는 속도 제한이 있습니다
2. **API 키 보호**: config.yaml에 API 키를 저장하지 마세요
3. **수동 모드 우선**: Amass는 가능하면 수동 모드 사용
4. **로봇 정책 준수**: robots.txt 존중

## 📚 추가 리소스

- **theHarvester**: https://github.com/laramies/theHarvester
- **OWASP Amass**: https://github.com/OWASP/Amass
- **Photon**: https://github.com/s0md3v/Photon
- **Sherlock**: https://github.com/sherlock-project/sherlock

## 🚧 향후 통합 예정 도구 (TODO)

다음 도구들은 향후 버전에서 통합될 예정입니다:

### 우선순위 높음
- [ ] **Recon-ng** - 모듈형 정찰 프레임워크
- [ ] **SpiderFoot** - 자동화된 OSINT 플랫폼 (200+ 소스)
- [ ] **Sublist3r** - 빠른 서브도메인 열거

### 우선순위 중간
- [ ] **Metagoofil** - 메타데이터 추출 (문서 파일)
- [ ] **DNSRecon** - DNS 정찰
- [ ] **Osintgram** - Instagram OSINT

### 우선순위 낮음
- [ ] **Maltego** - 링크 분석 및 시각화
- [ ] **FOCA** - 메타데이터 분석
- [ ] **GHunt** - Google 계정 정보 수집
- [ ] **Telegago** - Telegram 분석

### API 통합
- [ ] **SpiderFoot API** - API를 통한 통합
- [ ] **Recon-ng 모듈** - Python API 사용

### 데이터베이스/저장소
- [ ] **결과 데이터베이스** - SQLite/PostgreSQL 저장
- [ ] **결과 비교** - 시간 경과에 따른 변경사항 추적
- [ ] **캐싱 시스템** - 중복 스캔 방지

### 보고서 기능
- [ ] **통합 보고서** - 모든 도구 결과 통합
- [ ] **시각화** - 관계도 및 그래프
- [ ] **PDF 내보내기** - 전문적인 보고서 생성

---

**참고**: 이 도구들은 교육 및 승인된 보안 테스트 목적으로만 사용하세요.
