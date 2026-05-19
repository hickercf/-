FROM python:3.11-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

# 复制应用代码
COPY agent_app/ ./agent_app/
COPY kb_docs/ ./kb_docs/

# 非 root 用户运行
RUN useradd -m -u 1000 sandboxuser && chown -R sandboxuser:sandboxuser /app
USER sandboxuser

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

CMD ["python", "-m", "uvicorn", "agent_app.main:app", "--host", "0.0.0.0", "--port", "8080"]
