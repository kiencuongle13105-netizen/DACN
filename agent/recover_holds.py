"""Administrative emergency recovery of suspended processes from persisted holds."""
import argparse
import json
from pathlib import Path
from agent.two_stage import TwoStageController


def main():
    ap=argparse.ArgumentParser(description='Resume only identity-matching DACN held processes')
    ap.add_argument('--db', type=Path, default=Path(__file__).resolve().parents[1]/'data'/'holds.sqlite3')
    args=ap.parse_args()
    controller=TwoStageController(args.db,live=True)
    for row in controller.watchdog(all_pending=True):
        print(json.dumps(row,ensure_ascii=False))

if __name__=='__main__': main()
