"""Run the bundled synthetic log through parser, database and detection engine."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from config import Config
from database.db import initialize
from core.event_processor import process_log

if __name__=="__main__":
    initialize(Config.DATABASE)
    result=process_log((ROOT/"data"/"sample_auth.log").read_text(encoding="utf-8").splitlines(),Config.DATABASE,year=2025)
    print(f"Parsed {result['parsed']}; stored {result['inserted']} new events; generated {result['alerts']} new alerts.")
