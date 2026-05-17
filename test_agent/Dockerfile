FROM python:3.11-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制所有agent
COPY high_security_agent.py .
COPY medium_security_agent.py .
COPY low_security_agent.py .
COPY vulnerable_agent.py .
COPY start_all.py .

# 暴露端口
EXPOSE 50001 50002 50003 50004

# 启动所有agent
CMD ["python", "start_all.py"]
