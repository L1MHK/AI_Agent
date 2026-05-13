"""
1. 준비물: NVD API Key 발급
실시간으로 대량의 데이터를 가져오려면 API Key가 필수입니다.
NVD API Key 발급 페이지에서 이메일로 키를 미리 받아두세요.
https://nvd.nist.gov/developers/request-an-api-key
임베딩 모델 선택: 위 코드는 ChromaDB의 기본 임베딩을 사용합니다. 
업무용으로 더 정밀한 검색이 필요하다면 로컬 모델(all-MiniLM-L6-v2 등)로 교체하는 법을 바로 적용할 수 있습니다.
"""
import requests
import time
import chromadb
import config
import os
from datetime import datetime, timedelta
#from dotenv import load_dotenv
from config import *
#load_dotenv()

# --- [설정] ---
NVD_API_KEY = os.getenv("NVD_API_KEY")
#DB_PATH = os.getenv("DB_PATH")
#COLLECTION_NAME = "cve_full_2026"
client = chromadb.PersistentClient(path=DB_PATH)
collection = client.get_or_create_collection(name=COLLECTION_NAME)

# ... (상단 설정은 동일)

def run_final_ingestion():
    # 미래 시간 오차 방지를 위해 안전하게 '어제'를 종료일로 설정
    safe_today = datetime.now() - timedelta(days=1)
    
    intervals = [
        (safe_today - timedelta(days=90), safe_today),
        (safe_today - timedelta(days=180), safe_today - timedelta(days=91)),
        (safe_today - timedelta(days=270), safe_today - timedelta(days=181)),
        (safe_today - timedelta(days=360), safe_today - timedelta(days=271))
    ]

    for start_dt, end_dt in intervals:
        # NVD가 좋아하는 밀리초(.000)를 포함한 포맷
        start_str = start_dt.strftime("%Y-%m-%dT00:00:00.000")
        end_str = end_dt.strftime("%Y-%m-%dT23:59:59.999")
        
        curr_index = 0
        total_in_interval = 1
        
        print(f"\n📅 구간: {start_str[:10]} ~ {end_str[:10]} 수집 시작")

        while curr_index < total_in_interval:
            # 💡 핵심: params를 쓰지 않고 URL을 직접 구성하여 콜론(:) 인코딩 방지
            full_url = (
                f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?pubStartDate={start_str}"
                f"&pubEndDate={end_str}"
                f"&resultsPerPage=2000"
                f"&startIndex={curr_index}"
            )
            
            headers = {"apiKey": NVD_API_KEY}
            
            try:
                # params=params 대신 완성된 URL 사용
                response = requests.get(full_url, headers=headers, timeout=30)
                
                if response.status_code != 200:
                    print(f"⚠️ 대기 중... (Status: {response.status_code})")
                    time.sleep(30)
                    continue
                
                data = response.json()
                total_in_interval = data.get('totalResults', 0)
                
                # 로그 확인용: 여기서 total_in_interval이 34만 건이 아닌 수천 건이어야 함
                vulnerabilities = data.get('vulnerabilities', [])
                if not vulnerabilities: break

                docs, ids, metadatas = [], [], []
                for item in vulnerabilities:
                    cve = item['cve']
                    desc = cve['descriptions'][0]['value'] if cve['descriptions'] else "No description"
                    
                    metrics = cve.get('metrics', {})
                    cvss_data = (metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30') or [{}])[0].get('cvssData', {})
                    score = cvss_data.get('baseScore', 0)
                    
                    docs.append(desc)
                    ids.append(cve['id'])
                    metadatas.append({
                        "cve_id": cve['id'],
                        "severity": score,
                        "date": cve['published']
                    })
                
                collection.add(documents=docs, ids=ids, metadatas=metadatas)
                print(f"✅ 저장 중: {curr_index + len(docs)} / {total_in_interval}")
                
                curr_index += 2000
                time.sleep(6) 

            except Exception as e:
                print(f"❌ 오류 발생: {e}")
                time.sleep(10)
    print("\n✨ 모든 작업이 끝났습니다. 이제 최신 취약점 DB가 준비되었습니다!")

if __name__ == "__main__":
    # 실행 전 기존 DB 폴더를 삭제하고 하시는 것을 권장합니다 (rm -rf ./vulnerability_db)
    run_final_ingestion()