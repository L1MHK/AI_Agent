import os
from dotenv import load_dotenv

def setup_env():
    env_path = ".env"
    
    # 1. .env 파일이 없는 경우에만 실행
    if not os.path.exists(env_path):
        print("🔑 .env 파일이 발견되지 않았습니다. 초기 설정을 시작합니다.")
        
        configs = {
            "NVD_API_KEY": "NVD API Key",
            "TELEGRAM_BOT_TOKEN": "텔레그램 봇 토큰",
            "TELEGRAM_CHAT_ID": "텔레그램 Chat ID",
            "GEMINI_API_KEY": "Gemini API Key",
            "DB_PATH": "DB 저장 경로 (기본값: ./vulnerability_db)"
        }
        
        with open(env_path, "w", encoding="utf-8") as f:
            for key, desc in configs.items():
                value = input(f"[{key}] {desc}를 입력하세요: ")
                # DB_PATH의 경우 입력이 없으면 기본값 설정
                if key == "DB_PATH" and not value:
                    value = "./vulnerability_db"
                f.write(f"{key}={value}\n")
        
        print("✅ .env 파일 생성 완료.")
        
        # 새롭게 생성된 .env 내용을 현재 프로세스 메모리에 로드
        load_dotenv(env_path)
        return True  # 새로 생성됨
    
    print("✅ .env 파일이 이미 존재합니다.")
    return False

def run_db_ingestion():
    print("\n📦 NVD 취약점 데이터베이스 구축을 시작합니다...")
    
    try:
        # image_632b24.png에 정의된 함수를 임포트
        # .env가 로드된 후에 임포트해야 os.getenv가 정상 작동합니다.
        from ingest_nvd import run_final_ingestion
        
        if run_final_ingestion:
            run_final_ingestion()
            print("\n✅ DB 구축이 성공적으로 완료되었습니다!")
        else:
            print("\n❌ 에러: ingest_nvd.py에서 run_final_ingestion 함수를 찾을 수 없습니다.")
            
    except Exception as e:
        print(f"\n❌ DB 구축 중 예외 발생: {e}")