
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, Bot
from telegram.ext import Application, CallbackQueryHandler, ContextTypes
from telegram.constants import ParseMode
from config import *
from server_command import *
import os
import paramiko
from dotenv import load_dotenv
from google import genai
from datetime import datetime
from datetime import timedelta
import chromadb
from setup import *
import asyncio
import json
import re
import logging
from eoldb import get_eol_date_with_cache
from my_bot import TelegramSecurityBot
from server_command import *
"""
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

async def error_handler(update, context):
    #에러 발생 시 상세 내용을 로그에 기록합니다.
    logging.error(msg="Exception while handling an update:", exc_info=context.error)
"""


# --- 1단계: AI에게 명령어 후보 3개를 물어보는 함수 ---
def get_version_commands_from_ai(os_info, search_term, paths):
    # 1. 보안 규칙 정의 (가이드라인)
    security_rules = """
    [절대 규칙 - 보안 및 안정성]
    1. 당신은 오직 '읽기 전용(Read-only)' 명령어만 제안할 수 있습니다.
    2. 서버 설정을 변경하거나, 파일을 삭제(rm), 수정(vi, echo >), 이동(mv)하는 명령어는 절대 금지합니다.
    3. 서비스를 중단하거나 재시작하는 명령어(systemctl stop, reboot 등)도 절대 금지합니다.
    4. 오직 버전 확인을 위한 탐색 명령어(ls, cat, grep, find, jar -tvf, tar -tvf 등)만 사용하세요.
    5. 위 규칙을 어길 경우 시스템에 치명적인 영향을 줄 수 있으므로 반드시 준수하세요.
    6. 주의: 비밀번호를 입력해야 하거나 대기 상태가 필요한 명령어(예: mariadb의 -p 옵션 등)는 절대 제안하지 마세요. 모든 명령어는 비대화형(Non-interactive)으로 즉시 종료되어야 합니다.
    """
    generation_guide = """
    [명령어 생성 가이드 - 필독]
    1. 파일의 정보만 보는 'ls' 명령어는 절대 사용하지 마세요. (금지)
    2. 스크립트 파일(sh)을 찾았다면 반드시 'sh 경로' 또는 './경로' 형태로 실행하는 명령어를 제안하세요. 
    3. 실행 권한 문제로 실패할 것 같으면 'cat 경로'를 통해 파일 내용을 읽는 명령어를 제안하세요.
    4. Tomcat의 경우 반드시 'sh /opt/tomcat/bin/version.sh'를 실행하도록 유도하세요.
    """
    # 2. 실제 미션과 보안 규칙을 합침
    prompt = f"""
    {security_rules}
    {generation_guide}

    [미션]
    1. 톰캣의 경우 'version.sh'나 'catalina.sh version' 명령어를 최우선으로 고려하세요.
    2. jar 파일을 뒤질 때는 반드시 'grep -i version'처럼 대소문자를 구분하지 않는 옵션을 사용하세요.
    3. 'META-INF/MANIFEST.MF' 파일에 버전 정보가 있는지 확인하는 명령어를 제안하세요.
    OS 정보: {os_info}
    검색어: {search_term}
    찾은 경로들: {paths}

    위 경로들을 분석하여 '{search_term}'의 버전을 확인할 수 있는 안전한 명령어 3개를 우선순위대로 제안하세요.
    응답은 반드시 아래 JSON 형식으로만 하세요.

    {{
        "strategies": [
            {{"reason": "이유", "command": "명령어"}}
        ]
    }}
    """
    try:
        # 1. 변수 로드 확인
        #print(f"DEBUG: 사용 모델 -> {lanModel}") 
        
        response = ai_client.models.generate_content(
            model=lanModel, 
            contents=prompt,
            config={'temperature': 0.0}
        )
        
        raw_text = response.text
        #print(f"DEBUG: AI 응답 원본 -> {raw_text[:100]}...") # 응답이 오는지 확인

        # 2. JSON 파싱
        start = raw_text.find('{')
        end = raw_text.rfind('}')
        
        if start == -1:
            print("❌ 에러: AI 응답에 '{' 가 없습니다.")
            return None
            
        json_str = raw_text[start:end+1]
        return json.loads(json_str)

    except Exception as e:
        import traceback
        print("\n🆘 --- 에러 상세 발생 ---")
        print(traceback.format_exc()) 
        return None

def get_guidance_from_db(software, version):
    try:
        # 소프트웨어 이름과 버전으로 검색 (유사도 검색)
        query = f"{software} {version} vulnerability"
        
        # 💡 n_results를 3 정도로 늘려야 다양한 취약점을 AI가 판단할 수 있습니다.
        # 심각도(severity)가 높은 것 위주로 가져오도록 필터를 걸 수도 있습니다.
        results = collection.query(
            query_texts=[query], 
            n_results=3,
            where={"severity": {"$gt": 5.0}} # 심각도 5.0 이상인 것만 필터링
        )

        if results['documents'] and len(results['documents'][0]) > 0:
            # 검색된 여러 개의 CVE 설명을 하나로 합쳐서 AI에게 넘겨줍니다.
            combined_guidance = "\n\n".join([
                f"[{results['ids'][0][i]}] {doc}" 
                for i, doc in enumerate(results['documents'][0])
            ])
            return combined_guidance
            
        return "관련된 상세 취약점 정보가 DB에 없습니다."
    except Exception as e:
        return f"DB 조회 중 오류 발생: {str(e)}"

def get_detailed_analysis_from_ai(search_term, version_output, db_guidance,current_date):
    today_str = current_date.strftime("%Y-%m-%d")
    # DB에서 가져온 실제 CVE 내용(db_guidance)이 이제 이 프롬프트에 박힙니다.
        
    prompt = f"""
    당신은 숙련된 화이트해커 보안 분석가입니다. 
    분석 기준일: {today_str}

    [분석 대상]
    - 소프트웨어: {search_term}
    - 현재 설치된 정확한 버전: {version_output}
    - 검색된 취약점 후보(CVE): {db_guidance}

    [분석 미션: 정밀 매핑]
    1. 각 CVE에 기술된 '영향을 받는 버전(Affected Versions)' 범위에 현재 버전({version_output})이 **실제로 포함되는지** 철저히 검증하세요.
    2. 단순히 "권장 버전보다 낮다"는 이유로 취약하다고 판단하지 마세요.
    3. 만약 CVE 정보에 "10.1.0 ~ 10.1.40 버전에서 발생"이라고 되어 있다면, 현재 버전인 10.1.36은 이 범위에 속하므로 [해당사항있음]입니다.
    4. 반대로 현재 버전이 해당 CVE가 보고된 버전보다 높거나, 해당 취약점과 관련 없는 라인(예: 11.x 버전용 취약점)이라면 과감하게 [해당사항없음]으로 분류하세요.
    [출력 규칙 - 들여쓰기 필수]
    1. CVE 번호는 들여쓰기 공백 4칸으로 적습니다.
    2. 그 아래 세부 항목(요약, 관련여부 등)은 반드시 앞에 '공백 6칸'을 넣으세요.
    - 마크다운 기호(**, #, -, `)를 절대 사용하지 마세요.
    - 아래의 텍스트 양식과 띄어쓰기만 그대로 따라하세요(기본 들여쓰끼 4칸).
        [CVE-번호]
          - 요약 : [내용 요약]
          - 관련여부: 🚨 [해당사항있음] 또는 ⚪ [해당사항없음]
          - 사유: "10.1.36 버전은 이 취약점이 보고된 XXX~YYY 범위 안에 포함됨" 또는 "이 취약점은 XXX 버전 이후에 해결되었으므로 현재 버전은 안전함"
          - 대응: 해당 버전을 위한 구체적인 조치 방법
    """
    
    # AI 호출 (기존에 설정하신 모델 객체 사용)
    response = ai_client.models.generate_content(
        model=lanModel, 
        contents=prompt
    )
    return response.text
# --- 2단계: 서버 출력물을 보고 AI에게 EOS 날짜를 물어보는 함수 ---
def get_eos_date_from_ai(search_term, version_output, ref_date):
    # AI가 헷갈리지 않게 아주 단순하고 강력하게 지시합니다.
    prompt = f"""
    [입력 데이터]
    소프트웨어: {search_term}
    텍스트: {version_output}

    [미션]
    위 텍스트에서 {search_term}의 순수 버전 번호만 추출하세요. 
    (예: "Apache Tomcat/10.1.36" -> "10.1.36")
    (예: "PHP 8.0.30 (cli)" -> "8.0.30")

    반드시 아래 JSON 형식으로만 응답하세요. 다른 설명은 금지합니다.
    {{"version_summary": "추출된버전"}}
    """

    try:
        response = ai_client.models.generate_content(
            model=lanModel,
            contents=prompt,
            config={
                'temperature': 0.0, # 일관성을 위해 0으로 고정
                'top_p': 0.1,
            }
        )
        
        raw_text = response.text.strip()
        
        # 1. AI가 앞뒤에 붙인 마크다운(```json 등) 제거
        clean_text = re.sub(r'```json|```', '', raw_text).strip()
        
        # 2. JSON 파싱 시도
        json_start = clean_text.find('{')
        json_end = clean_text.rfind('}') + 1
        if json_start == -1 or json_end == 0:
             return {"version_summary": "Unknown", "eos_date": "0000-00-00", "is_official": False}
             
        json_str = clean_text[json_start:json_end]
        extracted = json.loads(json_str)
        
        v_num = extracted.get("version_summary", "Unknown")

        # 3. 공식 DB(eoldb.py) 조회
        # (이 함수가 이전에 만든 get_eol_date_with_cache를 호출해야 합니다)
        official_eol = get_eol_date_with_cache(search_term, v_num)

        if official_eol != "0000-00-00":
            return {"version_summary": v_num, "eos_date": official_eol, "is_official": True}
        else:
            # 공식 데이터 없으면 AI가 추론한 날짜라도 반환 (이전 프롬프트 미션에 날짜 추가 가능)
            return {"version_summary": v_num, "eos_date": "0000-00-00", "is_official": False}

    except Exception as e:
        print(f"   ⚠️ 파싱 에러 발생: {e}")
        return {"version_summary": "Unknown", "eos_date": "0000-00-00", "is_official": False}
# --- 서버 보조 함수들 ---
def run_remote_find(ssh_client, target_name):
    exclude_dirs = ["/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/nas"]
    exclude_str = " -o ".join([f'-path "{d}"' for d in exclude_dirs])
    command = (
        rf"find / \( {exclude_str} \) -prune -o "
        f"-iname '*{target_name}*' -type f -executable -print 2>/dev/null | head -n 10"
    )
    stdin, stdout, stderr = ssh_client.exec_command(command)
    return [line.strip() for line in stdout.readlines()]
def analyze_software_security(item, os_info, ssh):
    """
    한 개의 소프트웨어를 대상으로 [경로찾기 -> 버전추출 -> 분석]을 수행
    """
    ver = "N/A"
    guidance = "가이드 정보 없음"
    status = "⚠️ 분석 실패"
    success = False

    print(f"🔍 {item} 분석 시작...")
    
    # 1. 경로 찾기
    found_paths = run_remote_find(ssh, item)

    if not found_paths:
        print(f"   ❌ {item} 실행 파일을 찾을 수 없습니다.\n")
        return

    # 2. AI 명령어 생성
    analysis = get_version_commands_from_ai(os_info, item, found_paths)
    if not analysis or "strategies" not in analysis:
        print(f"   ⚠️ 분석 명령어를 생성하지 못했습니다.\n")
        return

    # 3. 명령어 시도 및 버전 출력 획득
    version_output = ""
    for i, strategy in enumerate(analysis["strategies"]):
        cmd = strategy["command"]
        print(f"   👉 시도 {i+1}: {cmd}")
        res = commandInput(ssh, cmd)
        if res and "Error" not in res and len(res) > 3:
            version_output = res
            success = True
            break

    # 4. 분석 결과 처리 (성공 시)
    if success:
        eos_info = get_eos_date_from_ai(item, version_output, CURRENT_DATE)
        if eos_info:
            ver = eos_info.get('version_summary', '알 수 없음')
            eos_str = eos_info.get('eos_date', 'Unknown')
            is_official = eos_info.get('is_official', False)
            
            source_mark = "[endoflife]" if is_official else "[AI추정]"
            
            # EOL 상태 판정
            try:
                eos_dt = datetime.strptime(eos_str, '%Y-%m-%d')
                warning_limit = CURRENT_DATE + timedelta(days=180)
                if eos_dt < CURRENT_DATE:
                    status = f"🚨 심각 ({source_mark} 지원 종료 초과: {eos_str})"
                elif eos_dt <= warning_limit:
                    status = f"⚠️ 위험 ({source_mark} 지원 종료 임박: {eos_str})"
                else:
                    status = f"✅ 안전 ({source_mark} 지원 종료 예정: {eos_str})"
            except:
                status = f"⚠️ 상태 불분명 ({eos_str})"
                
            # 취약점 DB 대조 및 AI 상세 분석
            db_knowledge = get_guidance_from_db(item, ver)
            guidance = get_detailed_analysis_from_ai(item, version_output, db_knowledge, CURRENT_DATE)

            print(f"   📊 확인된 버전: {ver}")
            print(f"   📋 최종 상태: {status}")
            print(f"   💡 보안 가이드: \n{guidance}")
    else:
        print(f"   🚫 버전 정보를 가져오는 데 실패했습니다.")
# --- [함수 2] 오픈소스 점검 통합 관리 (리스트를 인자로 받음) ---
def openSource(ssh, target_list):
    """
    넘겨받은 target_list를 순회하며 분석 실행
    """
    print("\n" + " # "*20)
    print("       OPEN SOURCE SECURITY REPORT")
    print(" # "*20)

    os_info = commandInput(ssh, "uname -a")
    print(f"OS Version: {os_info}\n")

    for item in target_list:
        analyze_software_security(item, os_info, ssh)
        print("-" * 60)

def searchSEV(check_point):

    result = collection.get(
       ids=[check_point]
       )
    if result['documents']: #RAG DB에 CEV 파일 있는경우 아래 함수 출력
           run_security_check(result)
           #print(f"ID: {result['ids'][0]}")
           #print(f"문서: {result['documents'][0]}")
    else:
           print("해당 ID를 찾을 수 없습니다.")
    return

def howCheckCEV(CEV_data):
    """
    1단계: 취약점 요약 및 점검 명령어 리스트 생성
    """
    os_info = commandInput(ssh, "uname -a")
    cve_id = CEV_data['ids'][0]
    cve_desc_en = CEV_data['documents'][0]

    prompt = f"""
    당신은 보안 전문가입니다. CVE ID: {cve_id}를 분석하세요.
    상세 내용(EN): {cve_desc_en}
    대상 OS: {os_info}

    [미션]
    1. 취약점의 핵심 내용을 한글로 요약(summary_ko)하세요.
    2. 이 서버가 해당 취약점에 노출되었는지 확인할 수 있는 '읽기 전용' 점검 명령어 리스트(checks)를 만드세요. (최대 3개)

    [응답 형식 - JSON]
    {{
        "summary_ko": "한글 요약",
        "checks": [
            {{"step": 1, "reason": "이유", "command": "명령어"}},
            ...
        ]
    }}
    """

    try:
        response = ai_client.models.generate_content(model=lanModel, contents=prompt)
        json_str = response.text[response.text.find('{'):response.text.rfind('}')+1]
        analysis = json.loads(json_str)
        
        # 분석 결과 리턴 (요약과 명령어 리스트)
        return cve_id, analysis.get('summary_ko'), analysis.get('checks', [])
    except Exception as e:
        print(f"❌ 분석 단계 오류: {e}")
        return cve_id, "분석 실패", []

def verifyVulnerability(cve_id, summary_ko, check_results):
    """
    2단계: 실행 결과값을 보고 AI에게 최종 위험 판정 요청
    """
    # 점검 결과 데이터를 텍스트로 정리
    results_str = ""
    for res in check_results:
        results_str += f"명령어: {res['command']}\n실행결과: {res['output']}\n\n"

    prompt = f"""
    당신은 화이트해커 보안 분석가입니다. 
    취약점({cve_id})에 대한 실제 서버 점검 결과 데이터를 분석하여 위험 여부를 판정하세요.

    [취약점 요약]
    {summary_ko}

    [점검 결과 데이터]
    {results_str}

    [미션]
    위 데이터를 바탕으로 이 서버의 상태를 **[🚨 위험]**, **[✅ 안전]**, **[⚪ 확인불가]** 중 하나로 판정하고, 
    그 근거를 보안 전문가 수준에서 짧게 설명하세요.
    """

    try:
        response = ai_client.models.generate_content(model=lanModel, contents=prompt)
        return response.text.strip()
    except Exception as e:
        return f"❌ 최종 검증 중 오류 발생: {e}"
# --- 메인 실행 로직 ---
# 취약점 검증을 위한 함수 model=lanModel 나중에 더 상급 언어모델로 변경
def validateCommands(cve_id, os_info, candidates):
    """
    AI를 사용하여 제안된 명령어의 안전성과 정확성을 재검증하는 함수
    """
    # 1. 후보 명령어가 없으면 즉시 빈 리스트 반환
    if not candidates:
        return []

    # 2. 검증 전용 프롬프트 구성
    # (응답 형식을 명확히 지정하여 파이썬이 읽기 좋게 만듭니다.)
    prompt = f"""
    당신은 까다로운 '시니어 보안 감사관'입니다. 
    제안된 명령어가 대상 서버({os_info})에서 실행되어도 안전한지 검사하십시오.

    [대상 취약점]
    {cve_id}

    [검토 대상 명령어 리스트]
    {json.dumps(candidates, indent=2, ensure_ascii=False)}

    [검사 기준 (중요)]
    1. '읽기 전용(Read-only)'인가? (파일 수정, 삭제, 서비스 중단 기능이 있으면 즉시 탈락)
    2. 해당 OS에서 실제 작동하는 명령어인가? (잘못된 옵션이나 존재하지 않는 명령어는 탈락)
    3. 시스템 부하가 적은가? (전체 파일 스캔 등은 탈락)
    4. 취약점 진단에 직접적으로 도움이 되는 정보인가? (무의미한 명령어 탈락)

    [응답 지침]
    - 서론이나 설명 없이 오직 아래 JSON 형식으로만 응답하십시오.
    - 안전이 확인되지 않은 명령어는 결과 리스트에서 완전히 제외하십시오.

    {{
        "validated_checks": [
            {{"step": 1, "reason": "안전함 및 필요성 설명", "command": "승인된 명령어"}},
            ...
        ]
    }}
    """

    try:
        # 3. AI 호출 (검증 단계이므로 온도를 낮게 설정하여 일관성 유지)
        # 나중에 lanModel 부분을 다른 모델 변수로 바꾸면 모델 교체가 됩니다.
        response = ai_client.models.generate_content(
            model=lanModel, 
            contents=prompt,
            config={'temperature': 0.1} # 낮을수록 더 보수적이고 정확해짐
        )
        
        raw_text = response.text
        
        # 4. JSON 데이터만 정교하게 추출
        start_idx = raw_text.find('{')
        end_idx = raw_text.rfind('}') + 1
        if start_idx == -1 or end_idx == 0:
            raise ValueError("AI 응답에서 JSON 형식을 찾을 수 없습니다.")
            
        json_str = raw_text[start_idx:end_idx]
        validated_data = json.loads(json_str)

        # 5. 최종 승인된 리스트 반환

        return validated_data.get('validated_checks', [])

    except Exception as e:
        print(f"⚠️ [검증 실패] {e}")
        # 에러 발생 시 안전을 위해 빈 리스트를 반환하여 아무것도 실행하지 않게 합니다.
        return []

def generateRemediationGuide(cve_id, summary_ko, verdict, check_results):
    # 실행 결과와 OS 정보를 하나의 텍스트로 병합
    context_data = ""
    for res in check_results:
        context_data += f"명령어: {res['command']}\n결과: {res['output']}\n"

    # AI에게 '선택지'를 주지 않고 '정답'만 요구하는 프롬프트
    prompt = f"""
    당신은 실전형 리눅스 커널/보안 엔지니어입니다. 
    CVE({cve_id}) 조치를 위해 서버에서 **즉시 실행 가능한 bash 명령어**만 작성하세요.

    [절대 규칙 - 반드시 준수]
    1. **OS 타겟팅:** 아래 데이터에서 확인된 OS({context_data})에 **전용 패키지 매니저(dnf/yum 또는 apt)** 명령어 하나만 선택하세요. 
    2. **혼합 금지:** 대상 OS가 Rocky/RHEL이면 'apt'는 절대로 언급하지 마세요. 반대도 마찬가지입니다.
    3. **자동화:** 설정 수정이 필요하면 반드시 `sed -i`를 사용하세요. 
    4. **형식:** 서론/설명/인사말은 모두 생략하세요. 오직 `# 주석`과 `실행 명령어`만 출력하세요.
    5. **확인:** 조치 후 상태를 검증하는 명령어(rpm -q 등)를 마지막에 포함하세요.

    [상황 요약]
    - 취약점: {summary_ko}
    - 판정: {verdict}
    - 점검기록: 
    {context_data}

    [출력 양식 예시]
    # 패키지 업데이트
    sudo dnf update -y systemd
    # 설정 수정
    sudo sed -i 's/Old/New/g' /etc/conf
    # 적용 및 확인
    sudo systemctl daemon-reexec && rpm -q systemd
    """

    try:
        # call_ai 인터페이스 사용 (없다면 client.models.generate_content 직접 호출로 수정 가능)
        response = ai_client.models.generate_content(
            model=lanModel, 
            contents=prompt,
            config={'temperature': 0.1} # 일관성을 위해 최저 온도로 설정
        )
        
        # 텍스트 결과값 반환
        return response.text.strip()
    except Exception as e:
        return f"❌ 조치 가이드 생성 실패: {e}"
    
def run_security_check(CEV_data):
    # 1. 시나리오 생성 및 진단 수행
    cve_id, summary, candidates = howCheckCEV(CEV_data)
    os_info = commandInput(ssh, "uname -a")
    
    # 2. 명령어 검증 및 수행
    print(f"🛡️ AI 보안 감사관이 점검 시나리오 검토 중...")
    safe_checks = validateCommands(cve_id, os_info, candidates)
    
    full_results = []
    for item in safe_checks:
        print(f"👉 실행: {item['command']}")
        output = commandInput(ssh, item['command'])
        item['output'] = output
        full_results.append(item)

    # 3. AI 최종 분석 (판정 및 조치 가이드 생성)
    # 한 번만 생성해서 변수에 담아 재사용합니다.
    print("\n🧐 AI 분석 결과 도출 중...")
    verdict = verifyVulnerability(cve_id, summary, full_results)
    
    # 위험하거나 확인 불가일 때만 가이드 생성
    guide_commands = ""
    if "[🚨 위험]" in verdict or "[⚪ 확인불가]" in verdict:
        guide_commands = generateRemediationGuide(cve_id, summary, verdict, full_results)
    
    # 4. [로컬 출력] 터미널에서 먼저 결과를 보여줍니다.
    print("-" * 60)
    print(verdict)
    if guide_commands:
        print("\n🛠️ AI 맞춤형 조치 가이드:")
        print(guide_commands)
    else:
        print("\n✅ 시스템이 안전하므로 별도의 조치가 필요하지 않습니다.")
    print("-" * 60)

    # 5. [텔레그램 보고] 조치가 필요한 경우에만 버튼과 함께 전송
    if guide_commands:
        print("📡 텔레그램으로 조치 리포트 전송 중...")
        report_message = (
            f"🚨 <b>보안 보고서: {cve_id}</b>\n\n"
            f"{verdict}\n\n"
            f"<b>[실행될 명령어]</b>\n<pre>{guide_commands}</pre>"
        )
        
        # 리포트 전송
        asyncio.run(sec_bot.send_report(report_message, guide_commands))
        
        print("✅ 모든 프로세스가 완료되었습니다. 텔레그램에서 승인 버튼을 기다립니다.")
        
        # 6. [중요] 여기서 멈춰서 관리자의 버튼 클릭을 기다립니다.
        # 이 코드가 실행되면 아래쪽 print는 Ctrl+C로 끄기 전까지 실행되지 않습니다.
        sec_bot.start_polling(executor_fn=ssh_executor)
    else:
        # 안전한 경우에는 굳이 버튼 대기를 할 필요가 없습니다.
        report_message = f"✅ <b>보안 보고서: {cve_id}</b>\n\n시스템이 안전합니다.\n\n{verdict}"
        asyncio.run(sec_bot.send_report(report_message))
        print("✅ 안전함 확인. 프로세스를 종료합니다.")

def ssh_executor(all_cmds):
    print("⚡ [관리자 승인] 테스트 모드 실행 (안전한 단일행 명령어)")
    
    # 각 줄이 그 자체로 완벽한 명령어가 되도록 구성
    test_cmds = [
        'echo "--- [1. 시스템 기본 정보] ---"',
        'hostname',
        'whoami',
        'uptime',
        'echo ""', # 줄바꿈 대용
        'echo "--- [2. 메모리 사용량] ---"',
        'free -h',
        'echo ""',
        'echo "--- [3. 디스크 사용량] ---"',
        'df -h | grep "^/dev/"',
        'echo ""',
        'echo "--- [4. 현재 디렉토리 파일 목록] ---"',
        'ls -lh | head -n 5'
    ]
    
    # 리스트를 줄바꿈으로 합쳐서 전달
    #all_cmds = "\n".join(test_cmds)
    
    result_report = adminCommandRunner(ssh, all_cmds)
    return result_report

if __name__ == "__main__":
    is_new_setup = setup_env()
    if is_new_setup or not os.path.exists("./vulnerability_db"):
        run_db_ingestion()
    # 1. AI 클라이언트 (이름을 ai_client로 변경)
    ai_client = genai.Client(api_key=API_KEY)
    
    # 2. 텔레그램 봇 생성 
    sec_bot = TelegramSecurityBot(TOKEN, CHAT_ID)

    # 3. DB 연결 (이름을 db_client로 변경)
    db_client = chromadb.PersistentClient(path=DB_PATH)
    collection = db_client.get_collection(name=COLLECTION_NAME)

    # 4. 점검 대상 오픈소스 
    openSourceList = ["tomcat", "php"]
    checkCEV = "CVE-2026-29111"


    for model in ai_client.models.list():
        print(model.name)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        input_ip = input(f"📍 접속할 서버 IP [{SERVER_IP}]: ").strip()
        #target_ip = input_ip if input_ip else SERVER_IP
        # 2. 계정 입력 (기본값: config.py의 SERVER_USER)
        input_user = input(f"👤 접속 계정 [{SERVER_USER}]: ").strip()
        input_pw = input(f"🔑 계정 패스워드 [{SERVER_PW}]: ").strip()
        #target_user = input_user if input_user else SERVER_USER
        ssh.connect(hostname=input_ip, username=input_user, password=input_pw)
        
        # main.py 또는 함수 내부
        print(f"🔑 API 키 로드 확인: {API_KEY[:10] if API_KEY else 'FAILED (None)'}...")
        openSource(ssh, openSourceList)
        # 2. 서버 CVE 점검 및 텔레그램 리포트 발송
        # (이 함수 내부에서 sec_bot.send_report()가 호출되어야 합니다)
        searchSEV(checkCEV)

        # 3. [핵심] 텔레그램 버튼 클릭 대기
        # 이 코드가 실행되면 프로그램은 여기서 멈춰서 버튼 클릭을 기다립니다.
        print("📡 텔레그램 응답 대기 중... (종료하려면 Ctrl+C)")
        sec_bot.start_polling(executor_fn=ssh_executor)
    except Exception as e:
        print(f"❌ 실행 중 오류 발생: {e}")
    finally:
        # 봇 대기가 종료(Ctrl+C)되면 SSH 연결을 닫습니다.
        ssh.close()
        print("🔒 SSH 연결이 종료되었습니다.")
