import os

def setup_env():
    env_path = ".env"
    
    if os.path.exists(env_path):
        confirm = input(".env 파일이 이미 존재합니다. 덮어쓰시겠습니까? (y/n): ")
        if confirm.lower() != 'y':
            return

    # 설정할 항목들
    configs = {
        "NVD_API_KEY": "NVD API Key를 입력하세요",
        "TELEGRAM_BOT_TOKEN": "텔레그램 봇 토큰을 입력하세요",
        "TELEGRAM_CHAT_ID": "텔레그램 Chat ID를 입력하세요",
        "GEMINI_API_KEY": "Gemini API Key를 입력하세요"
    }

    with open(env_path, "w", encoding="utf-8") as f:
        for key, description in configs.items():
            value = input(f"[{key}] {description}: ")
            f.write(f"{key}={value}\n")
    
    print("\n✅ .env 파일이 성공적으로 생성되었습니다.")
