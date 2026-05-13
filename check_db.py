import chromadb
from config import *
from eoldb import get_eol_date_with_cache
# 1. 수집된 DB 연결


client = chromadb.PersistentClient(path=DB_PATH)
collection = client.get_collection(name=COLLECTION_NAME)

def search_vulnerability(query):
    print(f"\n🔎 검색어: '{query}'")
    print("=" * 60)
    
    # 2. 유사도 기반 검색 (상위 3개 추출)
    results = collection.query(
        query_texts=["Tomcat RCE"],
        n_results=3,
    # severity가 0보다 큰(실제 취약점인) 것만 가져와!
        where={"severity": {"$gt": 0}} 
    )
    
    # 3. 결과 출력
    for i in range(len(results['ids'][0])):
        cve_id = results['ids'][0][i]
        document = results['documents'][0][i]
        metadata = results['metadatas'][0][i]
        
        print(f"[{i+1}] ID: {cve_id}")
        print(f"📊 심각도 점수: {metadata.get('severity', 'N/A')}")
        print(f"📅 발행일: {metadata.get('date', 'N/A')}")
        print(f"📝 요약: {document[:200]}...")
        print("-" * 60)

if __name__ == "__main__":
    # 질문하신 키워드로 검색 실행
    result = collection.get(
    ids=["CVE-2026-21858"]
    )
    if result['documents']:
        print(f"ID: {result['ids'][0]}")
        print(f"문서: {result['documents'][0]}")
    else:
        print("해당 ID를 찾을 수 없습니다.")
    #target_query = "CVE-2026-21858"
    #search_vulnerability(target_query)
    '''
    product = "ssh"
    version = "Linux localhost.localdomain 5.14.0-611.5.1.el9_7.aarch64 #1 SMP PREEMPT_DYNAMIC Tue Nov 11 23:15:17 UTC 2025 aarch64 aarch64 aarch64 GNU/Linux"
    eol_date = get_eol_date_with_cache(product, version)
    print(f"결과: {product} {version}의 EOL 날짜는 [{eol_date}] 입니다.")
    '''