import os
from google import genai
from config import *  # 변수명이 LAN_MODEL로 되어 있어야 함

ai_client = genai.Client(api_key=API_KEY)

def test_ai_connection():
    print(f"🔍 연결 테스트 시작...")
    print(f"📍 모델: {LAN_MODEL}")
    print(f"🔑 키 확인: {API_KEY[:10] if API_KEY else '❌ 키 없음'}...")
    for model in ai_client.models.list():
        print(model.name)
    try:
        # 클라이언트 초기화
        client = genai.Client(api_key=API_KEY)
        
        # 아주 짧은 질문 던지기
        response = client.models.generate_content(
            model=LAN_MODEL,
            contents="안녕? 너는 누구야? 아주 짧게 대답해줘."
        )
        
        print("\n✅ [연결 성공] AI 응답:")
        print(f"🤖 {response.text}")
        
    except Exception as e:
        print("\n❌ [연결 실패] 에러 내용:")
        print(e)

if __name__ == "__main__":
    test_ai_connection()