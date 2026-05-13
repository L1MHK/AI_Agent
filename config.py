import os
from dotenv import load_dotenv
from datetime import datetime
#from eoldb import get_eol_date_with_cache


load_dotenv()

CURRENT_DATE = datetime(2026, 5, 13) # 기준일
current_date = CURRENT_DATE

LAN_MODEL = "models/gemini-2.5-flash"
lanModel = LAN_MODEL

DB_PATH = "./vulnerability_db"
COLLECTION_NAME = "cve_full_2026"

SERVER_IP = os.getenv("SERVER_IP")
SERVER_USER = os.getenv("SERVER_USER")
SERVER_PW = os.getenv("SERVER_PW")
API_KEY = os.getenv("GEMINI_API_KEY")

TOKEN = os.getenv("TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

