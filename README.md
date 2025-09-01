cp .env.example .env
docker compose up --build

curl -s http://127.0.0.1:8000/health
# {"ok": true}
