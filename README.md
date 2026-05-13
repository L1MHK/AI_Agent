AI Security Agent 🛡️
AI를 활용하여 NVD(National Vulnerability Database) 취약점을 분석하고, 서버 상태를 점검하여 텔레그램으로 리포팅하는 자동화 도구입니다.

🚀 시작하기 전에 (준비물)
프로젝트를 원활하게 실행하기 위해 다음 사항들이 필요합니다.
1. NVD API Key 발급
실시간으로 대량의 취약점 데이터를 안정적으로 가져오기 위해 API Key가 필수입니다.
발급처: NVD API Key 발급 페이지에서 이메일로 키를 신청하고 미리 받아두세요.
https://nvd.nist.gov/developers/request-an-api-key
2. 텔레그램 봇 생성
분석된 리포트를 실시간으로 받기 위해 텔레그램 봇이 필요합니다.
BotFather를 통해 봇을 생성하고 API Token과 Chat ID를 준비하세요.
3. 점검 대상 서버 정보
점검을 수행할 서버의 IP, 접속 계정 및 SSH 키 등 접근 권한을 확인하세요

🛠️ 설치 및 설정
1. 저장소 복제 및 이동
git clone https://github.com/사용자아이디/AI_Agent.git
cd AI_Agent
2. 의존성 라이브러리 설치
pip install -r requirements.txt
3. 환경 변수 설정 (.env)
프로젝트 루트에 .env 파일을 생성하고 아래 내용을 입력하세요.
코드 스니펫
NVD_API_KEY=your_nvd_api_key
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
GEMINI_API_KEY=your_gemini_api_key

📖 사용 방법
1. 취약점 데이터베이스 구축
가장 먼저 NVD로부터 최신 취약점 데이터를 수집하여 로컬 DB를 생성해야 합니다.
python ingest_nvd.py
참고: 이 과정을 수행하면 vulnerability_db/ 폴더에 데이터가 구축됩니다. (최초 실행 시 시간이 다소 소요될 수 있습니다.)
2. 보안 에이전트 실행
DB 구축이 완료되면 메인 스크립트를 실행하여 분석 및 텔레그램 알림을 시작합니다.
python main.py
📁 주요 파일 설명
ingest_nvd.py: NVD API를 통해 취약점 데이터를 수집하고 벡터 DB를 구축합니다.
main.py: 전체 로직을 제어하고 분석 결과를 출력합니다.
my_bot.py: 텔레그램 봇과의 통신 및 메시지 전송을 담당합니다.
config.py: 프로젝트의 주요 설정값들을 관리합니다.



