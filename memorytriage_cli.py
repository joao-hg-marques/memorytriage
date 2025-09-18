import argparse
import os
from memorytriage_parser import run_triage_report

def main():
    parser = argparse.ArgumentParser(description="Memory Triage CLI - Who Launched What Edition")
    parser.add_argument('--mount', required=True, help='Mount point of MemProcFS')
    parser.add_argument('--report', required=True, help='Output HTML report path')
    args = parser.parse_args()

    findevil_path = os.path.join(args.mount, 'forensic', 'findevil', 'findevil.txt')
    proc_v_path = os.path.join(args.mount, 'sys', 'proc', 'proc-v.txt')
    timeline_path = os.path.join(args.mount, 'forensic', 'timeline', 'timeline_process.txt')
    ntfs_files_path = os.path.join(args.mount, 'forensic', 'ntfs', 'ntfs_files.txt')

    print("============================================================")
    print("                    🧠 MEMORY TRIAGE TOOL 🧠")
    print("                    Developed by Joao Marques")
    print("                https://github.com/joao-hg-marques")    
    print("============================================================\n")
    print("📡 Scanning in progress...")

    if not os.path.exists(findevil_path):
        print(f"❌ Error: Missing file {findevil_path}")
        return
    if not os.path.exists(proc_v_path):
        print(f"❌ Error: Missing file {proc_v_path}")
        return
    if not os.path.exists(timeline_path):
        print(f"⚠️  Warning: timeline_process.txt not found — continuing without timeline.")
        timeline_path = None
    if not os.path.exists(ntfs_files_path):
        print("ℹ️  ntfs_files.txt not found — continuing without NTFS section.")
        ntfs_files_path = None    

    run_triage_report(findevil_path, proc_v_path, timeline_path, args.report, ntfs_files_path)

    print(f"✅ Report generated: {args.report}")

if __name__ == '__main__':
    main()
