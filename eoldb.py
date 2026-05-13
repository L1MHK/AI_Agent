import requests
import chromadb
from datetime import datetime
from config import *

# 1. ChromaDB 설정 (기존 CVE DB와 같은 경로 사용 권장)
client = chromadb.PersistentClient(path=DB_PATH)

# EOS(End of Life) 정보를 담을 전용 컬렉션 생성
# 이미 존재하면 가져오고, 없으면 새로 만듭니다.
eol_collection = client.get_or_create_collection(name="software_lifecycle")

def get_eol_date_with_cache(product_name, current_version):
    """
    RAG 우선 조회 후, 데이터가 없으면 API 호출 및 DB 인서트를 수행합니다.
    """
    product = product_name.lower().strip()
    
    # 버전에서 '사이클(Major.Minor)' 추출 (예: 10.1.36 -> 10.1)
    version_parts = current_version.split('.')
    if len(version_parts) >= 2:
        cycle = f"{version_parts[0]}.{version_parts[1]}"
    else:
        cycle = version_parts[0]  # 메이저 버전만 있는 경우 대비
        
    target_id = f"{product}-{cycle}"

    # --- [Step 1] ChromaDB(RAG) 조회 ---
    try:
        # get()을 사용하여 ID로 정확히 조회 (유사도 검색보다 빠르고 정확함)
        db_result = eol_collection.get(ids=[target_id])
        
        if db_result['metadatas']:
            print(f"   ✅ [DB Hit] {target_id} 정보를 DB에서 찾았습니다.")
            return db_result['metadatas'][0]['eol_date']
    except Exception as e:
        print(f"   🔍 DB 조회 중 참고: {e}")

    # --- [Step 2] DB에 정보가 없는 경우 API 호출 (Fall-back) ---
    print(f"🌐 [API Call] DB에 {target_id} 정보가 없습니다. endoflife.date에서 데이터를 가져옵니다...")
    api_url = f"https://endoflife.date/api/{product}.json"
    
    try:
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            all_cycles = response.json()
            
            ids = []
            documents = []
            metadatas = []
            target_eol = "0000-00-00"

            # API에서 가져온 해당 제품의 모든 버전 정보를 DB에 한꺼번에 저장 (Batch Upsert)
            # 이렇게 하면 나중에 다른 버전을 검사할 때 API를 다시 안 불러도 됩니다.
            for item in all_cycles:
                c_name = item['cycle']
                # eol 값이 False(지원 중)인 경우 '지원 중'으로 표시, 날짜면 문자열로 변환
                raw_eol = item.get('eol', '0000-00-00')
                if isinstance(raw_eol, bool):
                    c_eol = "지원 중" if raw_eol is False else "지원 종료"
                else:
                    c_eol = str(raw_eol)

                c_id = f"{product}-{c_name}"
                
                ids.append(c_id)
                documents.append(f"{product} {c_name} 버전의 공식 지원 종료일(EOL)은 {c_eol}입니다.")
                metadatas.append({
                    "product": product, 
                    "cycle": c_name, 
                    "eol_date": c_eol,
                    "updated_at": datetime.now().strftime("%Y-%m-%d")
                })
                
                # 현재 우리가 찾는 버전과 일치하는 데이터 저장
                if c_name == cycle:
                    target_eol = c_eol

            # --- [Step 3] DB에 대량 인서트 (캐싱) ---
            eol_collection.upsert(
                ids=ids,
                documents=documents,
                metadatas=metadatas
            )
            print(f"   💾 [DB Update] {product}의 모든 사이클({len(ids)}개) 정보를 DB에 저장했습니다.")
            return target_eol
        
        else:
            print(f"   ⚠️ API 호출 실패 (Status: {response.status_code}). 해당 제품이 API 목록에 없을 수 있습니다.")
            return "0000-00-00"

    except Exception as e:
        print(f"   ❌ API 통신 오류: {e}")
        return "0000-00-00"