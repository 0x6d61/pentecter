# VulnBoard: 意図的に脆弱な Flask 掲示板アプリ（ペンテスト練習用）
# このイメージは教育・テスト目的のみで使用すること。
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# uploads ディレクトリ（Path Traversal テスト用）
RUN mkdir -p /app/uploads && echo "This is a sample file." > /app/uploads/sample.txt

EXPOSE 80
# nosemgrep: dockerfile.security.missing-user.missing-user -- intentionally vulnerable: command injection requires root to demonstrate privilege escalation
CMD ["python", "app.py"]
