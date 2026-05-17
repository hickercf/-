"""
test_agent 启动脚本

一键启动所有测试 Agent
"""
import subprocess
import sys
import time
import os

AGENTS = [
    {"name": "高安全 Agent", "file": "high_security_agent.py", "port": 50001},
    {"name": "中安全 Agent", "file": "medium_security_agent.py", "port": 50002},
    {"name": "低安全 Agent", "file": "low_security_agent.py", "port": 50003},
    {"name": "漏洞百出 Agent", "file": "vulnerable_agent.py", "port": 50004},
]


def start_agent(agent_info):
    """启动单个 Agent"""
    cmd = [
        sys.executable,
        agent_info["file"]
    ]
    
    print(f"启动 {agent_info['name']} (端口 {agent_info['port']})...")
    
    # 在Docker中不使用CREATE_NEW_CONSOLE
    if sys.platform == "win32" and not os.environ.get('DOCKER_ENV'):
        process = subprocess.Popen(
            cmd,
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    else:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    return process


def main():
    print("=" * 60)
    print("AgentFuzzer 测试 Agent 启动器")
    print("=" * 60)
    print()
    
    processes = []
    
    for agent in AGENTS:
        p = start_agent(agent)
        processes.append((agent, p))
        time.sleep(1)  # 间隔启动，避免端口冲突
    
    print()
    print("=" * 60)
    print("所有 Agent 已启动:")
    print("=" * 60)
    for agent in AGENTS:
        print(f"  {agent['name']:12} → http://127.0.0.1:{agent['port']}")
    print()
    print("回调接口: POST /callback")
    print("健康检查: GET  /health")
    print("系统提示: GET  /system_prompt")
    print()
    print("按 Ctrl+C 停止所有 Agent")
    print("=" * 60)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在停止所有 Agent...")
        for agent, p in processes:
            p.terminate()
            print(f"  已停止 {agent['name']}")
        print("全部停止完成")


if __name__ == "__main__":
    main()
