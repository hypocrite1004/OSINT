# 설치 가이드

## 빠른 시작

### 1. Python 설치 확인
```bash
python3 --version
# Python 3.7 이상이어야 합니다
```

### 2. 저장소 클론
```bash
git clone <repository-url>
cd OSINT
```

### 3. 가상 환경 생성 (권장)
```bash
# 가상 환경 생성
python3 -m venv venv

# 가상 환경 활성화
# Linux/Mac:
source venv/bin/activate
# Windows:
venv\Scripts\activate
```

### 4. 의존성 설치
```bash
pip install -r requirements.txt
```

### 5. 설정 파일 확인
```bash
# 기본 설정 파일 확인
cat osint_tool/configs/config.yaml

# 필요시 API 키 추가
nano osint_tool/configs/config.yaml
```

### 6. 테스트 실행
```bash
python osint_tool.py -t example.com
```

## 상세 설치 가이드

### Ubuntu/Debian
```bash
# 시스템 업데이트
sudo apt update && sudo apt upgrade -y

# Python 및 pip 설치
sudo apt install python3 python3-pip python3-venv -y

# 프로젝트 클론
git clone <repository-url>
cd OSINT

# 가상 환경 설정
python3 -m venv venv
source venv/bin/activate

# 의존성 설치
pip install -r requirements.txt

# 실행 권한 부여
chmod +x osint_tool.py
```

### CentOS/RHEL
```bash
# Python 3 설치
sudo yum install python3 python3-pip -y

# 나머지는 Ubuntu와 동일
```

### macOS
```bash
# Homebrew로 Python 설치
brew install python3

# 프로젝트 클론 및 설정
git clone <repository-url>
cd OSINT
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows
```powershell
# Python 3.7+ 다운로드 및 설치
# https://www.python.org/downloads/

# PowerShell에서:
git clone <repository-url>
cd OSINT
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## 선택적 도구 설치

### Nmap (포트 스캔 향상)
```bash
# Ubuntu/Debian
sudo apt install nmap -y

# macOS
brew install nmap

# Windows: https://nmap.org/download.html
```

### Amass (서브도메인 열거)
```bash
# Ubuntu/Debian
sudo apt install amass -y

# macOS
brew install amass
```

### Sublist3r
```bash
pip install sublist3r
```

## 문제 해결

### pip 설치 실패
```bash
# pip 업그레이드
pip install --upgrade pip

# 개별 패키지 설치 시도
pip install requests PyYAML dnspython python-whois
```

### SSL 오류
```bash
# 인증서 업데이트
pip install --upgrade certifi
```

### 권한 오류
```bash
# 가상 환경 사용 권장
# 또는 --user 플래그 사용
pip install --user -r requirements.txt
```

## 설치 확인

```bash
# Python 버전
python3 --version

# 설치된 패키지 확인
pip list

# 도구 실행 테스트
python osint_tool.py --help
```

## API 키 설정

### 1. config.yaml 복사 (선택사항)
```bash
cp osint_tool/configs/config.yaml osint_tool/configs/config_local.yaml
```

### 2. API 키 입력
```yaml
external_apis:
  shodan:
    enabled: true
    api_key: "YOUR_API_KEY_HERE"

  virustotal:
    enabled: true
    api_key: "YOUR_API_KEY_HERE"
```

### 3. 커스텀 설정으로 실행
```bash
python osint_tool.py -t example.com -c osint_tool/configs/config_local.yaml
```

## Docker 설치 (향후 지원 예정)

```bash
# Docker 이미지 빌드
docker build -t osint-tool .

# 실행
docker run -it osint-tool -t example.com
```

## 업데이트

```bash
# 최신 코드 받기
git pull origin main

# 의존성 업데이트
pip install --upgrade -r requirements.txt
```

## 제거

```bash
# 가상 환경 비활성화
deactivate

# 디렉토리 삭제
cd ..
rm -rf OSINT
```
