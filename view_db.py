#!/usr/bin/env python3
"""
Web Checker - Interactive Database Inspector CLI
Use this script to demonstrate the database schema and live table contents to supervisors.
"""
import sqlite3
import os
import sys

DB_PATH = os.path.join(os.path.dirname(__file__), "instance", "app.db")

def print_banner():
    print("=" * 80)
    print(" WEB CHECKER - RELATIONAL DATABASE INSPECTION ENGINE")
    print(f" Database File: {DB_PATH}")
    print("=" * 80)

def print_table(title, cur, query, max_width=32):
    cur.execute(query)
    rows = cur.fetchall()
    if not rows:
        print(f"\n[!] Table '{title}' is empty.\n")
        return

    cols = [desc[0] for desc in cur.description]
    # Calculate column widths
    widths = []
    for i, col in enumerate(cols):
        col_max = len(col)
        for r in rows:
            val_str = str(r[i]) if r[i] is not None else "NULL"
            if len(val_str) > max_width:
                val_str = val_str[:max_width-3] + "..."
            col_max = max(col_max, len(val_str))
        widths.append(col_max)

    header = " | ".join(col.ljust(widths[i]) for i, col in enumerate(cols))
    sep = "-+-".join("-" * widths[i] for i in range(len(cols)))
    
    print(f"\n[+] TABLE: {title.upper()} ({len(rows)} rows)")
    print(sep)
    print(header)
    print(sep)
    for r in rows:
        row_str = []
        for i, col in enumerate(cols):
            val_str = str(r[i]) if r[i] is not None else "NULL"
            if len(val_str) > max_width:
                val_str = val_str[:max_width-3] + "..."
            row_str.append(val_str.ljust(widths[i]))
        print(" | ".join(row_str))
    print(sep)

def main():
    if not os.path.exists(DB_PATH):
        print(f"Database file not found at {DB_PATH}")
        sys.exit(1)

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    print_banner()

    # 1. Users Table
    print_table(
        "users", 
        cur, 
        "SELECT userId, username, email, is_verified, created_at FROM users ORDER BY userId DESC LIMIT 8"
    )

    # 2. Scans Table
    print_table(
        "scans", 
        cur, 
        "SELECT scanId, targetUrl, status, progress, userId, created_at FROM scans ORDER BY created_at DESC LIMIT 8"
    )

    # 3. Sessions Table
    print_table(
        "sessions", 
        cur, 
        "SELECT id, userId, token_hash, created_at, expires_at FROM sessions ORDER BY id DESC LIMIT 8"
    )

    print("\nPresentation Tip: The full JSON findings for each scan are stored in `scans.results`.")
    print("=" * 80)
    con.close()

if __name__ == "__main__":
    main()
