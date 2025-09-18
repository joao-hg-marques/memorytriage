import os
import re
from html import escape
from dns_integration import generate_dns_section



def _normalize_win_path(p: str) -> str:
    r"""Add \\?\ prefix on Windows to handle long/virtual (Dokany) paths."""
    if os.name == "nt":
        p = os.path.abspath(p)
        if not p.startswith("\\\\?\\"):
            p = "\\\\?\\" + p
    return p

def _safe_read_text_file(path: str, max_bytes: int = 10 * 1024 * 1024):
    """
    Binary open + long-path prefix + tolerant decoding.
    Returns: (text, truncated_bool, encoding_used)
    """
    p = _normalize_win_path(path)
    with open(p, "rb") as f:
        data = f.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    for enc in ("utf-8", "utf-16-le", "utf-16-be", "latin-1"):
        try:
            return data.decode(enc, errors="replace"), truncated, enc
        except Exception:
            continue
    return data.decode("utf-8", errors="replace"), truncated, "utf-8"

def _copy_file_chunked(src: str, dst: str, chunk_size: int = 1024 * 1024):
    """Copy a possibly-virtual MemProcFS file to disk without loading it all in RAM."""
    p = _normalize_win_path(src)
    with open(p, "rb") as fsrc, open(dst, "wb") as fdst:
        while True:
            buf = fsrc.read(chunk_size)
            if not buf:
                break
            fdst.write(buf)

def run_triage_report(findevil_path, proc_v_path, timeline_path, output_path, ntfs_files_path=None):
    suspicious_pids = {}
    with open(findevil_path, "r", encoding="utf-8") as f:
        for line in f:
            if any(tag in line for tag in ["YR_RANSOMWARE", "YR_HACKTOOL", "PE_INJECT", "SYSTEM_IMPERSONATION", "HIGH_ENTROPY"]):
                parts = line.strip().split()
                if len(parts) >= 5:
                    try:
                        pid = str(int(parts[1]))
                        suspicious_pids[pid] = {
                            "procname": parts[2],
                            "type": parts[3],
                            "address": parts[4],
                            "desc": " ".join(parts[5:])
                        }
                    except ValueError:
                        continue

    matches = []
    with open(proc_v_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        for pid in suspicious_pids:
            if re.search(rf"\b{pid}\b", line):
                context = [lines[i].strip()]
                for j in range(1, 5):
                    if i + j < len(lines):
                        next_line = lines[i + j].strip()
                        if next_line != "" and not next_line.startswith("-"):
                            context.append(next_line)
                matches.append({
                    "PID": pid,
                    **suspicious_pids[pid],
                    "Details": "\n".join(context)
                })
                break

    timeline_hits = []
    if timeline_path and os.path.exists(timeline_path):
        with open(timeline_path, "r", encoding="utf-8") as f:
            timeline_lines = f.readlines()
        for line in timeline_lines:
            for pid in suspicious_pids:
                if re.search(rf"\b{pid}\b", line):
                    match = re.search(r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?(?P<ppid>\d+)\s+(?P<user>\S+)\s+(?P<path>\\Device.*)", line)
                    if match:
                        timeline_hits.append({
                            "pid": pid,
                            "timestamp": match.group("timestamp"),
                            "ppid": match.group("ppid"),
                            "user": match.group("user"),
                            "path": match.group("path")
                        })
                    else:
                        timeline_hits.append({
                            "pid": pid,
                            "timestamp": line[:19],
                            "ppid": "Unknown",
                            "user": "Unknown",
                            "path": line.strip()
                        })

    seen = set()
    triage_section = "<h2>Triage Results</h2><ul>"
    details_section = "<h2>Details</h2>"
    timeline_section = "<h2>Timeline: Who Launched What</h2><ul>"

    for row in matches:
        pid = row["PID"]
        if pid in seen:
            continue
        seen.add(pid)
        triage_section += f"<li>{escape(row['procname'])} (PID {pid})<br>"                           f"&nbsp;&nbsp;↳ Type: {escape(row['type'])}<br>"                           f"&nbsp;&nbsp;↳ Address: {escape(row['address'])}<br>"                           f"&nbsp;&nbsp;↳ Description: {escape(row['desc'])}</li>"
        details_section += f"<h3>{escape(row['procname'])} (PID {pid})</h3><pre>{escape(row['Details'])}</pre>"

    triage_section += "</ul>"

    for hit in timeline_hits:
         timeline_section += f"<li>[{escape(hit['timestamp'])}]<br>"   f"&nbsp;&nbsp;↳ PID {hit['pid']} launched by PID {hit['ppid']}<br>"                             f"&nbsp;&nbsp;↳ User: {escape(hit['user'])}<br>"                             f"&nbsp;&nbsp;↳ Path: {escape(hit['path'])}</li>"
        
    timeline_section += "</ul>"

    mount_root = os.path.abspath(os.path.join(findevil_path, os.pardir, os.pardir, os.pardir))
    dns_path = os.path.join(mount_root, "misc", "view", "txt", "sys", "net", "dns", "dns.txt")
    dns_section = generate_dns_section(dns_path) if os.path.exists(dns_path) else "<h2>DNS</h2><p>No DNS file found.</p>"

    ntfs_section = "<h2>NTFS Files</h2>"
    if ntfs_files_path and os.path.exists(ntfs_files_path):
        try:
            out_dir = os.path.dirname(os.path.abspath(output_path))
            full_name = "NTFS File"
            full_out = os.path.join(out_dir, full_name)

            _copy_file_chunked(ntfs_files_path, full_out)
            print(f"[+] NTFS: ntfs file found and exported to {full_out}")

            # show filesize in MB next to the link
            try:
                sz = os.path.getsize(full_out)
                mb = sz / (1024 * 1024)
                size_note = f" ({mb:.1f} MB)"
            except Exception:
                size_note = ""

            ntfs_section += f'<p><a href="{full_name}" download>Download full ntfs_files.txt</a>{size_note}</p>'
        except Exception as e:
            ntfs_section += f"<p>Could not export ntfs_files.txt: {escape(str(e))}</p>"
    else:
        ntfs_section += "<p>No ntfs_files.txt found.</p>"



    
    full_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>Memory Triage Report</title>
    <style>
        body {{ font-family: monospace; background: #f9f9f9; padding: 20px; }}
        h2 {{ color: #333; border-bottom: 1px solid #ccc; }}
        pre {{ background: #fff; padding: 10px; border: 1px solid #ddd; }}
    </style>
</head>
<body>
  <h1>&#129504; Memory Triage Report</h1>
    {triage_section}
    {details_section}
    {timeline_section}
    {dns_section}
    {ntfs_section}
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(full_html)

