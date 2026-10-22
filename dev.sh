#!/usr/bin/env bash
# Start the full Web Checker stack for local development.
#   backend API   -> http://localhost:5000
#   vulnerable tgt -> http://127.0.0.1:5001  (demo target to scan)
#   frontend      -> http://localhost:5173
set -e
cd "$(dirname "$0")"

cleanup_port() {
  local port="$1"
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "$port/tcp" 2>/dev/null || true
  else
    local pids
    pids=$(ss -ltnp 2>/dev/null | grep ":$port " | grep -oP 'pid=\K[0-9]+' | sort -u)
    [ -n "$pids" ] && kill $pids 2>/dev/null || true
  fi
}

echo "== Clearing any stale processes on ports 5000/5001/5173 (stale servers crash login with 500 errors) =="
cleanup_port 5000
cleanup_port 5001
cleanup_port 5173
sleep 1

mkdir -p /tmp/web_checker

echo "== Starting backend API (port 5000) =="
PYTHONPATH="$PWD" setsid nohup backend/venv/bin/python -u backend/app.py \
  > /tmp/web_checker/backend.log 2>&1 < /dev/null & disown
echo "backend pid: $!"

echo "== Starting vulnerable demo target (port 5001) =="
PYTHONPATH="$PWD" setsid nohup backend/venv/bin/python -u backend/tests/vulnerable_target.py \
  > /tmp/web_checker/target.log 2>&1 < /dev/null & disown
echo "target pid: $!"

echo "== Starting frontend (port 5173) =="
(
  cd frontend &&
  setsid nohup npm run dev > /tmp/web_checker/frontend.log 2>&1 < /dev/null &
) 
echo "frontend started"

echo ""
echo "Waiting for services..."
for i in $(seq 1 20); do
  backend_up=$(curl -s -m 1 -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/ 2>/dev/null || true)
  target_up=$(curl -s -m 1 -o /dev/null -w "%{http_code}" http://127.0.0.1:5001/ 2>/dev/null || true)
  frontend_up=$(curl -s -m 1 -o /dev/null -w "%{http_code}" http://127.0.0.1:5173/ 2>/dev/null || true)
  if [ "$backend_up" = "200" ] && [ "$target_up" = "200" ] && [ "$frontend_up" = "200" ]; then
    break
  fi
  sleep 1
done

echo "backend  :5000 -> ${backend_up:-down}"
echo "target   :5001 -> ${target_up:-down}"
echo "frontend :5173 -> ${frontend_up:-down}"

echo ""
echo "Open http://localhost:5173 to use the app."
echo "Logs:"
echo "  backend  /tmp/web_checker/backend.log"
echo "  target   /tmp/web_checker/target.log"
echo "  frontend /tmp/web_checker/frontend.log"