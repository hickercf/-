"""
sandbox/agent_app/rag_store.py — RAG 知识库存储

支持正常文档和注入测试文档。
"""
import os
from typing import List, Dict, Any

KB_DIR = os.path.join(os.path.dirname(__file__), "..", "kb_docs")
KB_DIR = os.path.normpath(KB_DIR)


class RAGStore:
    """模拟 RAG 知识库"""
    
    def __init__(self):
        self._injected_docs: List[Dict[str, Any]] = []
        self._load_default_docs()
    
    def _load_default_docs(self):
        """加载默认知识库文档"""
        self._default_docs = []
        
        # 读取文件
        default_files = ["normal_policy.txt", "refund_rule.txt"]
        for filename in default_files:
            filepath = os.path.join(KB_DIR, filename)
            if os.path.exists(filepath):
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                self._default_docs.append({
                    "doc_id": filename.replace(".txt", ""),
                    "title": filename.replace(".txt", "").replace("_", " ").title(),
                    "content": content,
                    "source": "default",
                })
    
    def inject_document(self, case_id: str, doc_title: str, doc_content: str):
        """注入测试文档"""
        self._injected_docs.append({
            "doc_id": case_id,
            "title": doc_title,
            "content": doc_content,
            "source": "injected",
        })
    
    def search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """模拟检索"""
        all_docs = self._default_docs + self._injected_docs
        
        # 简单关键词匹配
        results = []
        query_lower = query.lower()
        for doc in all_docs:
            score = 0
            if query_lower in doc["title"].lower():
                score += 10
            if query_lower in doc["content"].lower():
                score += 5
            
            # 分词匹配
            query_words = set(query_lower.split())
            title_words = set(doc["title"].lower().split())
            content_words = set(doc["content"].lower().split())
            score += len(query_words & title_words) * 3
            score += len(query_words & content_words) * 1
            
            if score > 0:
                results.append({**doc, "score": score})
        
        # 按分数排序
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]
    
    def get_all_docs(self) -> List[Dict[str, Any]]:
        """获取所有文档"""
        return self._default_docs + self._injected_docs
    
    def reset(self):
        """重置，清除注入的文档"""
        self._injected_docs = []


# 全局 RAG 存储实例
rag_store = RAGStore()
