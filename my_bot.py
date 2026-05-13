import asyncio
import html
import os
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, Bot
from telegram.ext import Application, CallbackQueryHandler, ContextTypes


class TelegramSecurityBot:
    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        self.pending_commands = ""
        self.executor_callback = None

    async def send_report(self, report_text, commands=""):
        """리포트 전송 시 하단에 '승인/거부' 버튼을 부착합니다."""
        self.pending_commands = commands
        
        # 1. HTML 특수문자(<, >, &)를 안전하게 변환
        # 이렇게 해야 정규표현식이나 쉘 명령어의 < 기호 때문에 터지지 않습니다.
        safe_report = html.escape(report_text)
        
        # 만약 리포트 제목 등에 강조를 넣고 싶다면, 
        # escape 처리가 끝난 문자열에 HTML 태그를 앞뒤로 붙여줍니다.
        final_text = f"🛡️ <b>AI 보안 감사 리포트</b>\n\n{safe_report}"

        # 2. 버튼 구성
        keyboard = [
            [
                InlineKeyboardButton("✅ 조치 승인 (실행)", callback_data='approve'),
                InlineKeyboardButton("❌ 거부", callback_data='deny')
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        # 3. 메시지 전송
        bot = Bot(token=self.token)
        try:
            await bot.send_message(
                chat_id=self.chat_id,
                text=final_text, # 안전하게 변환된 텍스트 사용
                reply_markup=reply_markup,
                parse_mode='HTML'
            )
            print("✅ 버튼이 포함된 리포트 전송 성공!")
        except Exception as e:
            print(f"❌ 리포트 전송 중 상세 오류: {e}")

    async def _handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()

        # 1. 거절(Deny) 클릭 시
        if query.data == 'deny':
            print("🔴 [사용자 응답] 거절(Deny) 클릭 - 즉시 종료합니다.")
            await query.edit_message_text(text="❌ <b>조치 거부됨:</b> 분석을 종료합니다.", parse_mode='HTML')
            
            # 여기서 바로 프로세스를 죽여야 아래의 executor_callback이 실행 안 됩니다.
            os._exit(0) 
            return # 뒤에 코드가 실행되지 않도록 차단

        # 2. 승인(Approve) 클릭 시
        if query.data == 'approve':
            await query.edit_message_text(text="⚙️ <b>승인 확인:</b> 서버 명령을 수행 중입니다...", parse_mode='HTML')
            
            if self.executor_callback:
                # 1. 서버 명령어 실행 결과 받아오기
                result_msg = await asyncio.to_thread(self.executor_callback, self.pending_commands)
                
                # 2. [핵심] 메시지 길이 체크 및 자르기
                # 텔레그램 제한은 4096자이지만, 안전하게 3800자에서 자릅니다.
                MAX_LEN = 3800 
                if len(result_msg) > MAX_LEN:
                    print(f"⚠️ 결과가 너무 길어 자릅니다. (전체: {len(result_msg)}자)")
                    safe_result = result_msg[:MAX_LEN] + "\n\n...(중략)...\n⚠️ <b>로그가 너무 길어 뒷부분이 생략되었습니다.</b>"
                else:
                    safe_result = result_msg

                # 3. 결과 보고 (자른 메시지로 전송)
                try:
                    await context.bot.send_message(
                        chat_id=self.chat_id, 
                        text=f"✅ <b>작업 완료 보고</b>\n\n{safe_result}",
                        parse_mode='HTML'
                    )
                except Exception as e:
                    # 혹시 HTML 태그가 잘려서 에러가 날 경우를 대비한 2차 방어
                    print(f"❌ 메시지 전송 최종 실패: {e}")
                    await context.bot.send_message(
                        chat_id=self.chat_id,
                        text="✅ <b>작업 완료:</b> 결과 로그가 너무 길거나 복잡하여 터미널을 확인해 주세요."
                    )

            print("🛑 [System] 모든 작업 완료. 프로그램을 종료합니다.")
            os._exit(0)
    def start_polling(self, executor_fn):
        """버튼 클릭을 기다리는 대기 모드 시작"""
        self.executor_callback = executor_fn
        app = Application.builder().token(self.token).build()
        
        # 버튼 클릭 이벤트 핸들러 등록
        app.add_handler(CallbackQueryHandler(self._handle_callback))
        
        print("📡 사용자의 버튼 클릭을 기다리는 중... (종료하려면 Ctrl+C)")
        app.run_polling()