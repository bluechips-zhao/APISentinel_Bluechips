"""
参数变异测试（Fuzzing）模块

本模块实现参数变异测试功能，支持 SQL 注入、XSS、路径遍历、命令注入等安全测试。
"""

import logging
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from ..core.http_client import HttpClient
from ..core.models import APIEndpoint, Parameter, TestResult


logger = logging.getLogger(__name__)


class Fuzzer:
    """
    参数变异测试类
    
    提供参数变异测试功能，支持多种安全漏洞检测 Payload。
    
    Attributes:
        payloads: Payload 库字典，按分类存储
        http_client: HTTP 客户端实例
    """
    
    DEFAULT_PAYLOADS = {
        "sqli": [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "' AND 1=1--",
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
        ],
        "command_injection": [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
        ],
        "custom": [],
    }
    
    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        verify_ssl: bool = True,
    ):
        """
        初始化 Fuzzer
        
        Args:
            timeout: 请求超时时间（秒），默认 30 秒
            max_retries: 最大重试次数，默认 3 次
            retry_delay: 重试延迟（秒），默认 1 秒
            verify_ssl: 是否验证 SSL 证书，默认 True
        """
        self._payloads: Dict[str, List[str]] = {
            category: list(payloads)
            for category, payloads in self.DEFAULT_PAYLOADS.items()
        }
        
        self._http_client = HttpClient(
            timeout=timeout,
            max_retries=max_retries,
            retry_delay=retry_delay,
            verify_ssl=verify_ssl,
        )
        
        logger.info("Fuzzer 初始化完成")
    
    def add_payload(self, category: str, payload: str) -> None:
        """
        添加自定义 Payload
        
        Args:
            category: Payload 分类（sqli/xss/path_traversal/command_injection/custom）
            payload: Payload 内容
            
        Example:
            >>> fuzzer = Fuzzer()
            >>> fuzzer.add_payload("sqli", "' OR '1'='1' #")
        """
        if category not in self._payloads:
            self._payloads[category] = []
        
        if payload not in self._payloads[category]:
            self._payloads[category].append(payload)
            logger.debug(f"Payload 已添加: category={category}, payload={payload[:30]}...")
    
    def add_payloads(self, category: str, payloads: List[str]) -> None:
        """
        批量添加 Payload
        
        Args:
            category: Payload 分类
            payloads: Payload 列表
            
        Example:
            >>> fuzzer = Fuzzer()
            >>> fuzzer.add_payloads("sqli", ["' OR 1=1--", "' OR 'a'='a"])
        """
        if category not in self._payloads:
            self._payloads[category] = []
        
        for payload in payloads:
            if payload not in self._payloads[category]:
                self._payloads[category].append(payload)
        
        logger.info(f"批量添加 Payload: category={category}, count={len(payloads)}")
    
    def remove_payload(self, category: str, payload: str) -> bool:
        """
        移除 Payload
        
        Args:
            category: Payload 分类
            payload: 要移除的 Payload
            
        Returns:
            是否成功移除
            
        Example:
            >>> fuzzer = Fuzzer()
            >>> fuzzer.remove_payload("sqli", "' OR '1'='1")
        """
        if category not in self._payloads:
            logger.warning(f"分类不存在: {category}")
            return False
        
        if payload in self._payloads[category]:
            self._payloads[category].remove(payload)
            logger.debug(f"Payload 已移除: category={category}, payload={payload[:30]}...")
            return True
        
        logger.warning(f"Payload 不存在: category={category}, payload={payload[:30]}...")
        return False
    
    def get_payloads(self, category: Optional[str] = None) -> List[str]:
        """
        获取 Payload 列表
        
        Args:
            category: Payload 分类，如果为 None 则返回所有 Payload
            
        Returns:
            Payload 列表
            
        Example:
            >>> fuzzer = Fuzzer()
            >>> payloads = fuzzer.get_payloads("sqli")
            >>> all_payloads = fuzzer.get_payloads()
        """
        if category is None:
            all_payloads = []
            for cat_payloads in self._payloads.values():
                all_payloads.extend(cat_payloads)
            return all_payloads
        
        return list(self._payloads.get(category, []))
    
    def load_payloads_from_file(self, file_path: str, category: str) -> int:
        """
        从文件加载 Payload
        
        文件格式：每行一个 Payload
        
        Args:
            file_path: 文件路径
            category: Payload 分类
            
        Returns:
            加载的 Payload 数量
            
        Raises:
            FileNotFoundError: 文件不存在
            
        Example:
            >>> fuzzer = Fuzzer()
            >>> count = fuzzer.load_payloads_from_file("payloads.txt", "sqli")
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        if category not in self._payloads:
            self._payloads[category] = []
        
        loaded_count = 0
        
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                payload = line.strip()
                if payload and payload not in self._payloads[category]:
                    self._payloads[category].append(payload)
                    loaded_count += 1
        
        logger.info(f"从文件加载 Payload: file={file_path}, category={category}, count={loaded_count}")
        
        return loaded_count
    
    def generate_mutations(
        self,
        original_value: Any,
        categories: Optional[List[str]] = None,
    ) -> List[Any]:
        """
        生成变异值
        
        根据原始值类型和指定的分类生成变异值列表。
        
        Args:
            original_value: 原始参数值
            categories: Payload 分类列表，如果为 None 则使用所有分类
            
        Returns:
            变异值列表
            
        Example:
            >>> fuzzer = Fuzzer()
            >>> mutations = fuzzer.generate_mutations("test", ["sqli", "xss"])
        """
        mutations = []
        
        if categories is None:
            categories = ["sqli", "xss", "path_traversal", "command_injection"]
        
        for category in categories:
            payloads = self.get_payloads(category)
            mutations.extend(payloads)
        
        if isinstance(original_value, str):
            for category in categories:
                payloads = self.get_payloads(category)
                for payload in payloads:
                    mutated = original_value + payload
                    if mutated not in mutations:
                        mutations.append(mutated)
        
        logger.debug(f"生成变异值: original_type={type(original_value).__name__}, count={len(mutations)}")
        
        return mutations
    
    def fuzz_parameter(
        self,
        param_name: str,
        param_value: Any,
        category: Optional[str] = None,
    ) -> List[Any]:
        """
        对单个参数进行变异
        
        Args:
            param_name: 参数名称
            param_value: 原始参数值
            category: Payload 分类，如果为 None 则使用所有分类
            
        Returns:
            变异后的参数值列表
            
        Example:
            >>> fuzzer = Fuzzer()
            >>> mutations = fuzzer.fuzz_parameter("username", "admin", "sqli")
        """
        categories = [category] if category else None
        mutations = self.generate_mutations(param_value, categories)
        
        logger.info(
            f"参数变异: param={param_name}, "
            f"original_type={type(param_value).__name__}, "
            f"mutations_count={len(mutations)}"
        )
        
        return mutations
    
    def fuzz_endpoint(
        self,
        endpoint: APIEndpoint,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        对接口所有参数进行变异
        
        Args:
            endpoint: API 接口对象
            category: Payload 分类，如果为 None 则使用所有分类
            
        Returns:
            变异后的参数组合列表，每个元素是一个参数字典
            
        Example:
            >>> fuzzer = Fuzzer()
            >>> endpoint = APIEndpoint(url="https://api.example.com/users", method="GET", path="/users")
            >>> mutations = fuzzer.fuzz_endpoint(endpoint, "sqli")
        """
        mutations_list = []
        
        if not endpoint.parameters:
            logger.warning(f"接口没有参数: {endpoint.path}")
            return mutations_list
        
        for param in endpoint.parameters:
            param_mutations = self.fuzz_parameter(
                param.name,
                param.default_value or "",
                category
            )
            
            for mutation in param_mutations:
                mutation_dict = {
                    "param_name": param.name,
                    "param_type": param.param_type,
                    "original_value": param.default_value,
                    "mutated_value": mutation,
                    "category": category or "all",
                }
                mutations_list.append(mutation_dict)
        
        logger.info(
            f"接口参数变异: path={endpoint.path}, "
            f"params_count={len(endpoint.parameters)}, "
            f"total_mutations={len(mutations_list)}"
        )
        
        return mutations_list
    
    def analyze_response(
        self,
        response: requests.Response,
        original_response: Optional[requests.Response] = None,
    ) -> Dict[str, Any]:
        """
        分析响应差异
        
        对比变异请求的响应与原始响应，检测潜在的安全漏洞。
        
        Args:
            response: 变异请求的响应
            original_response: 原始请求的响应（可选）
            
        Returns:
            分析结果字典，包含：
            - status_code: 状态码
            - response_length: 响应长度
            - has_error: 是否包含错误信息
            - error_indicators: 错误指示器列表
            - status_changed: 状态码是否变化
            - length_changed: 响应长度是否变化
            - potential_vulnerability: 是否存在潜在漏洞
            
        Example:
            >>> fuzzer = Fuzzer()
            >>> analysis = fuzzer.analyze_response(response, original_response)
        """
        error_indicators = [
            "sql syntax",
            "mysql",
            "oracle",
            "postgresql",
            "sqlite",
            "syntax error",
            "unclosed quotation",
            "odbc",
            "jdbc",
            "warning",
            "error",
            "exception",
            "stack trace",
            "script error",
            "alert(",
            "xss",
            "directory listing",
            "no such file",
            "command not found",
            "/bin/",
            "/etc/",
            "root:",
            "uid=",
            "gid=",
        ]
        
        response_text = response.text.lower()
        
        has_error = any(indicator in response_text for indicator in error_indicators)
        
        found_indicators = [
            indicator
            for indicator in error_indicators
            if indicator in response_text
        ]
        
        analysis = {
            "status_code": response.status_code,
            "response_length": len(response.content),
            "has_error": has_error,
            "error_indicators": found_indicators,
            "status_changed": False,
            "length_changed": False,
            "length_difference": 0,
            "potential_vulnerability": has_error,
        }
        
        if original_response is not None:
            analysis["status_changed"] = (
                response.status_code != original_response.status_code
            )
            
            length_diff = abs(len(response.content) - len(original_response.content))
            analysis["length_difference"] = length_diff
            analysis["length_changed"] = length_diff > 100
            
            if analysis["status_changed"] or analysis["length_changed"]:
                analysis["potential_vulnerability"] = True
        
        if analysis["potential_vulnerability"]:
            logger.warning(
                f"检测到潜在漏洞: status_code={response.status_code}, "
                f"has_error={has_error}, indicators={found_indicators[:3]}"
            )
        
        return analysis
    
    def test_endpoint(
        self,
        endpoint: APIEndpoint,
        http_client: Optional[HttpClient] = None,
        category: Optional[str] = None,
    ) -> List[TestResult]:
        """
        测试接口并返回结果
        
        对接口进行参数变异测试，发送变异请求并分析响应。
        
        Args:
            endpoint: API 接口对象
            http_client: HTTP 客户端实例（可选，默认使用内部客户端）
            category: Payload 分类，如果为 None 则使用所有分类
            
        Returns:
            TestResult 列表
            
        Example:
            >>> fuzzer = Fuzzer()
            >>> endpoint = APIEndpoint(url="https://api.example.com/users", method="GET", path="/users")
            >>> results = fuzzer.test_endpoint(endpoint)
        """
        client = http_client or self._http_client
        results: List[TestResult] = []
        
        mutations = self.fuzz_endpoint(endpoint, category)
        
        if not mutations:
            logger.warning(f"没有生成变异: {endpoint.path}")
            return results
        
        original_response = None
        try:
            if endpoint.method.upper() == "GET":
                original_response = client.get(endpoint.url)
            elif endpoint.method.upper() == "POST":
                original_response = client.post(endpoint.url)
            elif endpoint.method.upper() == "PUT":
                original_response = client.put(endpoint.url)
            elif endpoint.method.upper() == "DELETE":
                original_response = client.delete(endpoint.url)
        except Exception as e:
            logger.warning(f"原始请求失败: {e}")
        
        for mutation in mutations:
            request_id = str(uuid.uuid4())
            param_name = mutation["param_name"]
            param_type = mutation["param_type"]
            mutated_value = mutation["mutated_value"]
            
            logger.info(
                f"Fuzzing 测试: request_id={request_id}, "
                f"param={param_name}, value={str(mutated_value)[:30]}..."
            )
            
            request_headers = dict(endpoint.headers)
            request_body = ""
            
            kwargs = {
                "headers": request_headers,
            }
            
            if endpoint.method.upper() == "GET":
                kwargs["params"] = {param_name: mutated_value}
            else:
                if param_type == "query":
                    kwargs["params"] = {param_name: mutated_value}
                elif param_type == "body":
                    request_headers["Content-Type"] = "application/json"
                    request_body = f'{{"{param_name}": "{mutated_value}"}}'
                    kwargs["data"] = request_body
                elif param_type == "header":
                    request_headers[param_name] = str(mutated_value)
            
            start_time = time.time()
            error_msg = ""
            response_status = 0
            response_headers: Dict[str, str] = {}
            response_body = ""
            response_length = 0
            
            try:
                response = client.request(
                    method=endpoint.method,
                    url=endpoint.url,
                    **kwargs
                )
                
                response_status = response.status_code
                response_headers = dict(response.headers)
                response_body = response.text
                response_length = len(response.content)
                
                analysis = self.analyze_response(response, original_response)
                
                if analysis["potential_vulnerability"]:
                    logger.warning(
                        f"潜在漏洞发现: param={param_name}, "
                        f"indicators={analysis['error_indicators'][:3]}"
                    )
                
            except Exception as e:
                error_msg = str(e)
                logger.error(f"请求失败: {error_msg}")
            
            end_time = time.time()
            response_time = end_time - start_time
            
            result = TestResult(
                request_id=request_id,
                endpoint=endpoint,
                request_headers=request_headers,
                request_body=request_body,
                response_status=response_status,
                response_headers=response_headers,
                response_body=response_body,
                response_length=response_length,
                response_time=response_time,
                sensitive_info=[],
                timestamp=datetime.now(),
                error=error_msg,
            )
            
            results.append(result)
        
        logger.info(f"Fuzzing 测试完成: path={endpoint.path}, results_count={len(results)}")
        
        return results
    
    def get_categories(self) -> List[str]:
        """
        获取所有 Payload 分类
        
        Returns:
            分类列表
        """
        return list(self._payloads.keys())
    
    def get_payload_count(self, category: Optional[str] = None) -> int:
        """
        获取 Payload 数量
        
        Args:
            category: Payload 分类，如果为 None 则返回总数
            
        Returns:
            Payload 数量
        """
        if category is None:
            return sum(len(payloads) for payloads in self._payloads.values())
        
        return len(self._payloads.get(category, []))
    
    def clear_payloads(self, category: Optional[str] = None) -> None:
        """
        清空 Payload
        
        Args:
            category: Payload 分类，如果为 None 则清空所有
        """
        if category is None:
            self._payloads = {
                cat: [] for cat in self.DEFAULT_PAYLOADS.keys()
            }
            logger.info("所有 Payload 已清空")
        else:
            if category in self._payloads:
                self._payloads[category] = []
                logger.info(f"分类 Payload 已清空: {category}")
    
    def set_proxy(self, proxy: str) -> None:
        """
        设置代理
        
        Args:
            proxy: 代理地址
        """
        self._http_client.set_proxy(proxy)
        logger.info(f"Fuzzer 代理已设置: {proxy}")
    
    def clear_proxy(self) -> None:
        """清除代理设置"""
        self._http_client.clear_proxy()
        logger.info("Fuzzer 代理已清除")
    
    def set_default_headers(self, headers: Dict[str, str]) -> None:
        """
        设置默认请求头
        
        Args:
            headers: 请求头字典
        """
        self._http_client.set_default_headers(headers)
        logger.info(f"Fuzzer 默认请求头已设置: {list(headers.keys())}")
    
    def close(self) -> None:
        """关闭 Fuzzer"""
        self._http_client.close()
        logger.info("Fuzzer 已关闭")
    
    def __enter__(self) -> "Fuzzer":
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """上下文管理器出口"""
        self.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取统计信息
        
        Returns:
            包含统计信息的字典
        """
        return {
            "categories": self.get_categories(),
            "total_payloads": self.get_payload_count(),
            "payloads_by_category": {
                cat: len(payloads)
                for cat, payloads in self._payloads.items()
            },
            "http_client_info": self._http_client.get_session_info(),
        }
