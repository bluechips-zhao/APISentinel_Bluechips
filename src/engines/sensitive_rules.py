"""
敏感信息检测规则库

提供云服务密钥、Token、数据库连接串、个人隐私信息等敏感信息的检测规则。
支持自定义规则的添加、删除、导入导出等功能。
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional


class SensitiveRuleLibrary:
    """敏感信息检测规则库"""

    def __init__(self):
        self._rules: Dict[str, Dict] = {}
        self._initialize_default_rules()

    def _initialize_default_rules(self):
        """初始化默认规则"""
        self._init_cloud_key_rules()
        self._init_token_rules()
        self._init_database_rules()
        self._init_personal_info_rules()

    def _init_cloud_key_rules(self):
        """初始化云服务密钥检测规则"""
        cloud_rules = [
            {
                "name": "AWS Access Key ID",
                "pattern": r"AKIA[0-9A-Z]{16}",
                "level": "High",
                "description": "AWS 访问密钥 ID",
                "category": "cloud_key"
            },
            {
                "name": "AWS Secret Access Key",
                "pattern": r"[A-Za-z0-9/+=]{40}",
                "level": "High",
                "description": "AWS 访问密钥 Secret",
                "category": "cloud_key"
            },
            {
                "name": "Aliyun Access Key ID",
                "pattern": r"LTAI[0-9a-zA-Z]{12,20}",
                "level": "High",
                "description": "阿里云访问密钥 ID",
                "category": "cloud_key"
            },
            {
                "name": "Aliyun Access Key Secret",
                "pattern": r"[0-9a-zA-Z]{30}",
                "level": "High",
                "description": "阿里云访问密钥 Secret",
                "category": "cloud_key"
            },
            {
                "name": "Tencent Cloud SecretId",
                "pattern": r"AKID[0-9a-zA-Z]{32}",
                "level": "High",
                "description": "腾讯云访问密钥 ID",
                "category": "cloud_key"
            },
            {
                "name": "Tencent Cloud SecretKey",
                "pattern": r"[0-9a-zA-Z]{32}",
                "level": "High",
                "description": "腾讯云访问密钥 Secret",
                "category": "cloud_key"
            },
            {
                "name": "Google Cloud API Key",
                "pattern": r"AIza[0-9A-Za-z-_]{35}",
                "level": "High",
                "description": "Google Cloud API 密钥",
                "category": "cloud_key"
            },
            {
                "name": "Azure Key",
                "pattern": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                "level": "High",
                "description": "Azure 访问密钥",
                "category": "cloud_key"
            }
        ]
        for rule in cloud_rules:
            self._rules[rule["name"]] = rule

    def _init_token_rules(self):
        """初始化 Token 检测规则"""
        token_rules = [
            {
                "name": "JWT Token",
                "pattern": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
                "level": "High",
                "description": "JWT 认证令牌",
                "category": "token"
            },
            {
                "name": "GitHub Token",
                "pattern": r"ghp_[0-9a-zA-Z]{36}",
                "level": "High",
                "description": "GitHub 个人访问令牌",
                "category": "token"
            },
            {
                "name": "GitHub OAuth Token",
                "pattern": r"gho_[0-9a-zA-Z]{36}",
                "level": "High",
                "description": "GitHub OAuth 令牌",
                "category": "token"
            },
            {
                "name": "Slack Token",
                "pattern": r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24}",
                "level": "High",
                "description": "Slack 访问令牌",
                "category": "token"
            },
            {
                "name": "Stripe API Key",
                "pattern": r"sk_live_[0-9a-zA-Z]{24}",
                "level": "High",
                "description": "Stripe API 密钥",
                "category": "token"
            },
            {
                "name": "PayPal Client ID",
                "pattern": r"[A-Za-z0-9_-]{80}",
                "level": "Medium",
                "description": "PayPal 客户端 ID",
                "category": "token"
            }
        ]
        for rule in token_rules:
            self._rules[rule["name"]] = rule

    def _init_database_rules(self):
        """初始化数据库连接串检测规则"""
        database_rules = [
            {
                "name": "MySQL Connection String",
                "pattern": r"mysql://[^:]+:[^@]+@[^/]+/[^?]+",
                "level": "High",
                "description": "MySQL 数据库连接字符串",
                "category": "database"
            },
            {
                "name": "PostgreSQL Connection String",
                "pattern": r"postgresql://[^:]+:[^@]+@[^/]+/[^?]+",
                "level": "High",
                "description": "PostgreSQL 数据库连接字符串",
                "category": "database"
            },
            {
                "name": "MongoDB Connection String",
                "pattern": r"mongodb://[^:]+:[^@]+@[^/]+/[^?]+",
                "level": "High",
                "description": "MongoDB 数据库连接字符串",
                "category": "database"
            },
            {
                "name": "Redis Connection String",
                "pattern": r"redis://[^:]+:[^@]+@[^/]+/[^?]+",
                "level": "High",
                "description": "Redis 数据库连接字符串",
                "category": "database"
            }
        ]
        for rule in database_rules:
            self._rules[rule["name"]] = rule

    def _init_personal_info_rules(self):
        """初始化个人隐私信息检测规则"""
        personal_rules = [
            {
                "name": "Chinese Mobile Phone",
                "pattern": r"1[3-9]\d{9}",
                "level": "Medium",
                "description": "中国手机号码",
                "category": "personal_info"
            },
            {
                "name": "Chinese ID Card",
                "pattern": r"[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]",
                "level": "High",
                "description": "中国身份证号码",
                "category": "personal_info"
            },
            {
                "name": "Email Address",
                "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                "level": "Low",
                "description": "电子邮箱地址",
                "category": "personal_info"
            },
            {
                "name": "Bank Card Number",
                "pattern": r"[1-9]\d{15,18}",
                "level": "High",
                "description": "银行卡号",
                "category": "personal_info"
            },
            {
                "name": "IP Address",
                "pattern": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                "level": "Low",
                "description": "IP 地址",
                "category": "personal_info"
            }
        ]
        for rule in personal_rules:
            self._rules[rule["name"]] = rule

    def add_rule(self, name: str, pattern: str, level: str = "Medium", 
                 description: str = "", category: str = "custom") -> bool:
        """
        添加自定义规则

        Args:
            name: 规则名称
            pattern: 正则表达式模式
            level: 风险等级 (High/Medium/Low)
            description: 规则描述
            category: 规则分类

        Returns:
            是否添加成功
        """
        if name in self._rules:
            return False
        
        if level not in ["High", "Medium", "Low"]:
            level = "Medium"
        
        try:
            re.compile(pattern)
        except re.error:
            return False
        
        self._rules[name] = {
            "name": name,
            "pattern": pattern,
            "level": level,
            "description": description,
            "category": category
        }
        return True

    def remove_rule(self, name: str) -> bool:
        """
        移除规则

        Args:
            name: 规则名称

        Returns:
            是否移除成功
        """
        if name in self._rules:
            del self._rules[name]
            return True
        return False

    def get_rules(self) -> List[Dict]:
        """
        获取所有规则

        Returns:
            规则列表
        """
        return list(self._rules.values())

    def get_rules_by_category(self, category: str) -> List[Dict]:
        """
        根据分类获取规则

        Args:
            category: 规则分类

        Returns:
            规则列表
        """
        return [rule for rule in self._rules.values() if rule["category"] == category]

    def get_rules_by_level(self, level: str) -> List[Dict]:
        """
        根据风险等级获取规则

        Args:
            level: 风险等级 (High/Medium/Low)

        Returns:
            规则列表
        """
        return [rule for rule in self._rules.values() if rule["level"] == level]

    def get_rule(self, name: str) -> Optional[Dict]:
        """
        获取指定规则

        Args:
            name: 规则名称

        Returns:
            规则字典，不存在则返回 None
        """
        return self._rules.get(name)

    def load_rules_from_file(self, file_path: str) -> bool:
        """
        从文件加载规则（JSON 格式）

        Args:
            file_path: 文件路径

        Returns:
            是否加载成功
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return False
            
            with open(path, 'r', encoding='utf-8') as f:
                rules_data = json.load(f)
            
            if not isinstance(rules_data, list):
                return False
            
            for rule in rules_data:
                if not isinstance(rule, dict):
                    continue
                
                name = rule.get("name")
                pattern = rule.get("pattern")
                if not name or not pattern:
                    continue
                
                level = rule.get("level", "Medium")
                description = rule.get("description", "")
                category = rule.get("category", "custom")
                
                self.add_rule(name, pattern, level, description, category)
            
            return True
        except (json.JSONDecodeError, IOError, Exception):
            return False

    def save_rules_to_file(self, file_path: str) -> bool:
        """
        保存规则到文件（JSON 格式）

        Args:
            file_path: 文件路径

        Returns:
            是否保存成功
        """
        try:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(list(self._rules.values()), f, ensure_ascii=False, indent=2)
            
            return True
        except (IOError, Exception):
            return False

    def detect(self, text: str, categories: Optional[List[str]] = None) -> List[Dict]:
        """
        检测文本中的敏感信息

        Args:
            text: 待检测文本
            categories: 要检测的规则分类列表，为 None 则检测所有

        Returns:
            检测结果列表，每项包含规则信息和匹配内容
        """
        results = []
        
        for rule in self._rules.values():
            if categories and rule["category"] not in categories:
                continue
            
            try:
                pattern = re.compile(rule["pattern"])
                matches = pattern.findall(text)
                
                if matches:
                    results.append({
                        "rule": rule,
                        "matches": matches
                    })
            except re.error:
                continue
        
        return results

    def __len__(self) -> int:
        """返回规则数量"""
        return len(self._rules)

    def __contains__(self, name: str) -> bool:
        """检查规则是否存在"""
        return name in self._rules


sensitive_rule_library = SensitiveRuleLibrary()
