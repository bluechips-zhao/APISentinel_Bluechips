"""
认证绕过检测模块

本模块实现自动认证绕过漏洞检测功能，包括 Token 绕过、HTTP 方法绕过、请求头绕过等测试。
"""

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple
from copy import deepcopy

import requests

from ..core.http_client import HttpClient
from ..core.models import APIEndpoint


logger = logging.getLogger(__name__)


class AuthBypassDetector:
    """
    认证绕过检测器
    
    用于检测 API 接口的认证绕过漏洞，包括 Token 绕过、HTTP 方法绕过、请求头绕过等。
    
    Attributes:
        http_client: HTTP 客户端实例
    """
    
    BYPASS_SUCCESS_CODES = [200, 201, 202, 204]
    AUTH_FAILURE_CODES = [401, 403]
    
    def __init__(self, http_client: Optional[HttpClient] = None):
        """
        初始化 AuthBypassDetector
        
        Args:
            http_client: HTTP 客户端实例（可选，不提供则自动创建）
        """
        self.http_client = http_client or HttpClient()
        logger.info("AuthBypassDetector 初始化完成")
    
    def _execute_bypass_tests(
        self,
        test_type: str,
        test_type_label: str,
        endpoint: APIEndpoint,
        http_client: HttpClient,
        test_cases: List[Dict[str, Any]],
        apply_modification: Callable[
            [APIEndpoint, Dict[str, Any], Dict[str, Any]],
            Tuple[APIEndpoint, Dict[str, str], Optional[str]]
        ],
        original_headers: Optional[Dict[str, str]] = None,
        original_response: Optional[requests.Response] = None
    ) -> List[Dict]:
        """
        执行绕过测试的模板方法
        
        封装完整的测试执行流程：获取原始响应、遍历测试用例、
        应用修改、发送请求、分析结果、构建结果字典、异常处理、日志记录。
        
        Args:
            test_type: 测试类型标识（如 "token_bypass"）
            test_type_label: 测试类型中文标签（如 "Token 绕过"）
            endpoint: API 接口对象
            http_client: HTTP 客户端实例
            test_cases: 测试用例列表，每个用例需包含 name 和 description
            apply_modification: 应用修改的函数，接收 (endpoint, original_headers, test_case)，
                返回 (modified_endpoint, modified_headers, modified_method)
            original_headers: 用于获取原始响应的请求头（默认使用 endpoint.headers）
            original_response: 可选的预获取原始响应（传入后跳过原始响应获取，用于复用）
            
        Returns:
            测试结果列表
        """
        logger.info(f"开始 {test_type_label} 测试: {endpoint.method} {endpoint.path}")
        
        results = []
        request_headers = original_headers or endpoint.headers
        
        try:
            if original_response is None:
                original_response = self._send_request(endpoint, http_client, request_headers)
            
            for test_case in test_cases:
                try:
                    modified_endpoint, modified_headers, modified_method = apply_modification(
                        endpoint, request_headers, test_case
                    )
                    
                    test_response = self._send_request(
                        modified_endpoint, http_client, modified_headers
                    )
                    
                    analysis = self.analyze_bypass(original_response, test_response)
                    
                    result = self._build_success_result(
                        test_type, test_case, endpoint,
                        original_response, test_response, analysis,
                        modified_headers, modified_method
                    )
                    results.append(result)
                    
                    if analysis["bypass_success"]:
                        self._log_bypass_found(
                            test_type_label, test_case["name"],
                            original_response, test_response
                        )
                
                except Exception as e:
                    logger.error(f"{test_type_label} 测试失败 [{test_case['name']}]: {e}")
                    results.append(
                        self._build_error_result(test_type, test_case, endpoint, str(e))
                    )
        
        except Exception as e:
            logger.error(f"获取原始响应失败: {e}")
            return []
        
        logger.info(f"{test_type_label} 测试完成，共 {len(results)} 个测试")
        return results
    
    def _build_success_result(
        self,
        test_type: str,
        test_case: Dict[str, Any],
        endpoint: APIEndpoint,
        original_response: Optional[requests.Response],
        test_response: Optional[requests.Response],
        analysis: Dict[str, Any],
        modified_headers: Dict[str, str],
        modified_method: Optional[str] = None
    ) -> Dict[str, Any]:
        """构建成功的测试结果字典"""
        result = {
            "test_type": test_type,
            "test_name": test_case["name"],
            "description": test_case["description"],
            "endpoint": f"{endpoint.method} {endpoint.path}",
            "original_status": original_response.status_code if original_response else None,
            "test_status": test_response.status_code if test_response else None,
            "bypass_success": analysis["bypass_success"],
            "risk_level": analysis["risk_level"],
            "details": analysis["details"],
        }
        
        if modified_method is not None:
            result["modified_method"] = modified_method
        else:
            result["modified_headers"] = modified_headers
        
        return result
    
    def _build_error_result(
        self,
        test_type: str,
        test_case: Dict[str, Any],
        endpoint: APIEndpoint,
        error_msg: str
    ) -> Dict[str, Any]:
        """构建错误的测试结果字典"""
        return {
            "test_type": test_type,
            "test_name": test_case["name"],
            "description": test_case["description"],
            "endpoint": f"{endpoint.method} {endpoint.path}",
            "error": error_msg,
            "bypass_success": False,
            "risk_level": "Unknown"
        }
    
    def _log_bypass_found(
        self,
        test_type_label: str,
        test_name: str,
        original_response: Optional[requests.Response],
        test_response: Optional[requests.Response]
    ) -> None:
        """记录发现绕过漏洞的警告日志"""
        logger.warning(
            f"发现 {test_type_label} 漏洞: {test_name} - "
            f"状态码 {original_response.status_code if original_response else 'N/A'} -> "
            f"{test_response.status_code if test_response else 'N/A'}"
        )
    
    def test_token_bypass(self, endpoint: APIEndpoint, http_client: HttpClient) -> List[Dict]:
        """
        测试 Token 绕过
        
        测试多种 Token 绕过方式：
        - 空 Token：移除 Authorization 头
        - 过期 Token：使用过期的 Token
        - 无效 Token：使用格式错误的 Token
        - 空 Bearer：Bearer 后无内容
        - 错误格式：使用 Basic 等其他认证方式
        
        Args:
            endpoint: API 接口对象
            http_client: HTTP 客户端实例
            
        Returns:
            绕过测试结果列表
        """
        original_headers = deepcopy(endpoint.headers)
        
        test_cases = [
            {
                "name": "empty_token",
                "description": "移除 Authorization 头",
                "headers_modifier": lambda h: {k: v for k, v in h.items() if k.lower() != "authorization"}
            },
            {
                "name": "expired_token",
                "description": "使用过期的 Token",
                "headers_modifier": lambda h: {**h, "Authorization": "Bearer expired_token_12345"}
            },
            {
                "name": "invalid_token",
                "description": "使用格式错误的 Token",
                "headers_modifier": lambda h: {**h, "Authorization": "Bearer invalid!@#$%"}
            },
            {
                "name": "empty_bearer",
                "description": "Bearer 后无内容",
                "headers_modifier": lambda h: {**h, "Authorization": "Bearer "}
            },
            {
                "name": "wrong_format_basic",
                "description": "使用 Basic 认证格式",
                "headers_modifier": lambda h: {**h, "Authorization": "Basic invalid_base64"}
            },
            {
                "name": "wrong_format_invalid",
                "description": "使用错误的 Token 格式",
                "headers_modifier": lambda h: {**h, "Authorization": "Bearer invalid_token_format"}
            },
        ]
        
        def apply_token_modification(
            ep: APIEndpoint,
            orig_headers: Dict[str, str],
            case: Dict[str, Any]
        ) -> Tuple[APIEndpoint, Dict[str, str], None]:
            modified_headers = case["headers_modifier"](deepcopy(orig_headers))
            return ep, modified_headers, None
        
        return self._execute_bypass_tests(
            test_type="token_bypass",
            test_type_label="Token 绕过",
            endpoint=endpoint,
            http_client=http_client,
            test_cases=test_cases,
            apply_modification=apply_token_modification,
            original_headers=original_headers
        )
    
    def test_method_bypass(self, endpoint: APIEndpoint, http_client: HttpClient) -> List[Dict]:
        """
        测试 HTTP 方法绕过
        
        测试多种 HTTP 方法绕过方式：
        - GET → POST
        - POST → GET
        - PUT → POST
        - DELETE → GET
        - 添加 X-HTTP-Method-Override 头
        
        Args:
            endpoint: API 接口对象
            http_client: HTTP 客户端实例
            
        Returns:
            绕过测试结果列表
        """
        original_method = endpoint.method.upper()
        
        method_mappings = {
            "GET": ["POST", "PUT", "DELETE"],
            "POST": ["GET", "PUT", "DELETE"],
            "PUT": ["POST", "GET", "DELETE"],
            "DELETE": ["GET", "POST", "PUT"],
            "PATCH": ["GET", "POST", "PUT", "DELETE"]
        }
        
        alternative_methods = method_mappings.get(original_method, ["GET", "POST"])
        
        method_replacement_cases = [
            {
                "name": f"{original_method}_to_{alt}",
                "description": f"方法替换: {original_method} -> {alt}",
                "alt_method": alt
            }
            for alt in alternative_methods
        ]
        
        method_override_cases = [
            {
                "name": f"override_to_{alt}",
                "description": f"X-HTTP-Method-Override: {alt}",
                "override_method": alt
            }
            for alt in alternative_methods
        ]
        
        def apply_method_replacement(
            ep: APIEndpoint,
            orig_headers: Dict[str, str],
            case: Dict[str, Any]
        ) -> Tuple[APIEndpoint, Dict[str, str], str]:
            modified_ep = deepcopy(ep)
            modified_ep.method = case["alt_method"]
            return modified_ep, modified_ep.headers, case["alt_method"]
        
        def apply_method_override(
            ep: APIEndpoint,
            orig_headers: Dict[str, str],
            case: Dict[str, Any]
        ) -> Tuple[APIEndpoint, Dict[str, str], None]:
            modified_headers = deepcopy(ep.headers)
            modified_headers["X-HTTP-Method-Override"] = case["override_method"]
            return ep, modified_headers, None
        
        try:
            original_response = self._send_request(endpoint, http_client, endpoint.headers)
        except Exception as e:
            logger.error(f"获取原始响应失败: {e}")
            return []
        
        results = self._execute_bypass_tests(
            test_type="method_bypass",
            test_type_label="方法绕过",
            endpoint=endpoint,
            http_client=http_client,
            test_cases=method_replacement_cases,
            apply_modification=apply_method_replacement,
            original_response=original_response
        )
        
        override_results = self._execute_bypass_tests(
            test_type="method_bypass",
            test_type_label="方法覆盖绕过",
            endpoint=endpoint,
            http_client=http_client,
            test_cases=method_override_cases,
            apply_modification=apply_method_override,
            original_response=original_response
        )
        
        results.extend(override_results)
        return results
    
    def test_header_bypass(self, endpoint: APIEndpoint, http_client: HttpClient) -> List[Dict]:
        """
        测试请求头绕过
        
        测试多种请求头绕过方式：
        - X-Forwarded-For: 127.0.0.1
        - X-Original-URL: 修改后的 URL
        - X-Rewrite-URL: 修改后的 URL
        - X-Custom-IP-Authorization: 127.0.0.1
        - X-Real-IP: 127.0.0.1
        
        Args:
            endpoint: API 接口对象
            http_client: HTTP 客户端实例
            
        Returns:
            绕过测试结果列表
        """
        original_headers = deepcopy(endpoint.headers)
        
        test_cases = [
            {
                "name": "x_forwarded_for",
                "description": "X-Forwarded-For: 127.0.0.1",
                "headers": {"X-Forwarded-For": "127.0.0.1"}
            },
            {
                "name": "x_forwarded_for_array",
                "description": "X-Forwarded-For: 127.0.0.1, 127.0.0.2",
                "headers": {"X-Forwarded-For": "127.0.0.1, 127.0.0.2"}
            },
            {
                "name": "x_real_ip",
                "description": "X-Real-IP: 127.0.0.1",
                "headers": {"X-Real-IP": "127.0.0.1"}
            },
            {
                "name": "x_custom_ip_auth",
                "description": "X-Custom-IP-Authorization: 127.0.0.1",
                "headers": {"X-Custom-IP-Authorization": "127.0.0.1"}
            },
            {
                "name": "x_original_url",
                "description": "X-Original-URL: / (根路径)",
                "headers": {"X-Original-URL": "/"}
            },
            {
                "name": "x_original_url_public",
                "description": "X-Original-URL: /public (公共路径)",
                "headers": {"X-Original-URL": "/public"}
            },
            {
                "name": "x_rewrite_url",
                "description": "X-Rewrite-URL: / (根路径)",
                "headers": {"X-Rewrite-URL": "/"}
            },
            {
                "name": "x_rewrite_url_public",
                "description": "X-Rewrite-URL: /public (公共路径)",
                "headers": {"X-Rewrite-URL": "/public"}
            },
            {
                "name": "x_host",
                "description": "X-Host: localhost",
                "headers": {"X-Host": "localhost"}
            },
            {
                "name": "x_forwarded_host",
                "description": "X-Forwarded-Host: localhost",
                "headers": {"X-Forwarded-Host": "localhost"}
            },
            {
                "name": "x_forwarded_server",
                "description": "X-Forwarded-Server: localhost",
                "headers": {"X-Forwarded-Server": "localhost"}
            },
            {
                "name": "client_ip",
                "description": "Client-IP: 127.0.0.1",
                "headers": {"Client-IP": "127.0.0.1"}
            },
            {
                "name": "true_client_ip",
                "description": "True-Client-IP: 127.0.0.1",
                "headers": {"True-Client-IP": "127.0.0.1"}
            },
            {
                "name": "x_originating_ip",
                "description": "X-Originating-IP: 127.0.0.1",
                "headers": {"X-Originating-IP": "127.0.0.1"}
            },
        ]
        
        def apply_header_modification(
            ep: APIEndpoint,
            orig_headers: Dict[str, str],
            case: Dict[str, Any]
        ) -> Tuple[APIEndpoint, Dict[str, str], None]:
            modified_headers = deepcopy(orig_headers)
            modified_headers.update(case["headers"])
            return ep, modified_headers, None
        
        return self._execute_bypass_tests(
            test_type="header_bypass",
            test_type_label="请求头绕过",
            endpoint=endpoint,
            http_client=http_client,
            test_cases=test_cases,
            apply_modification=apply_header_modification,
            original_headers=original_headers
        )
    
    def analyze_bypass(
        self,
        original_response: Optional[requests.Response],
        test_response: Optional[requests.Response]
    ) -> Dict[str, Any]:
        """
        分析绕过结果
        
        对比原始响应和测试响应，判断是否绕过成功，并标记风险等级。
        
        判断逻辑：
        1. 状态码从 401/403 变为 200 等成功状态码 -> 绕过成功
        2. 响应内容发生显著变化 -> 可能绕过
        3. 响应长度显著增加 -> 可能绕过
        
        Args:
            original_response: 原始响应对象
            test_response: 测试响应对象
            
        Returns:
            分析结果字典，包含：
            - bypass_success: 是否绕过成功
            - risk_level: 风险等级 (High/Medium/Low/None)
            - details: 详细信息
        """
        analysis = {
            "bypass_success": False,
            "risk_level": "None",
            "details": {}
        }
        
        if not original_response or not test_response:
            analysis["details"]["error"] = "响应对象为空"
            return analysis
        
        original_status = original_response.status_code
        test_status = test_response.status_code
        
        analysis["details"]["original_status"] = original_status
        analysis["details"]["test_status"] = test_status
        
        if original_status in self.AUTH_FAILURE_CODES and test_status in self.BYPASS_SUCCESS_CODES:
            analysis["bypass_success"] = True
            analysis["risk_level"] = "High"
            analysis["details"]["reason"] = f"状态码从 {original_status} 变为 {test_status}，认证被绕过"
            return analysis
        
        if original_status in self.AUTH_FAILURE_CODES and test_status not in self.AUTH_FAILURE_CODES:
            analysis["bypass_success"] = True
            analysis["risk_level"] = "Medium"
            analysis["details"]["reason"] = f"状态码从 {original_status} 变为 {test_status}，可能存在绕过"
            return analysis
        
        original_body = original_response.text or ""
        test_body = test_response.text or ""
        
        if original_body != test_body:
            original_len = len(original_body)
            test_len = len(test_body)
            
            if original_len > 0:
                length_ratio = abs(test_len - original_len) / original_len
            else:
                length_ratio = 1.0 if test_len > 0 else 0.0
            
            analysis["details"]["original_length"] = original_len
            analysis["details"]["test_length"] = test_len
            analysis["details"]["length_ratio"] = round(length_ratio, 2)
            
            if length_ratio > 0.5:
                analysis["bypass_success"] = True
                analysis["risk_level"] = "Medium"
                analysis["details"]["reason"] = f"响应内容长度变化 {length_ratio:.2%}，可能存在绕过"
                return analysis
            elif length_ratio > 0.1:
                analysis["risk_level"] = "Low"
                analysis["details"]["reason"] = f"响应内容长度变化 {length_ratio:.2%}，需人工验证"
        
        if original_status == test_status:
            analysis["details"]["reason"] = "状态码和响应内容未发生变化，绕过失败"
        else:
            analysis["details"]["reason"] = f"状态码从 {original_status} 变为 {test_status}，但未达到绕过标准"
        
        return analysis
    
    def scan_endpoint(self, endpoint: APIEndpoint, http_client: HttpClient) -> List[Dict]:
        """
        扫描接口的认证绕过漏洞
        
        对单个接口执行所有类型的绕过测试。
        
        Args:
            endpoint: API 接口对象
            http_client: HTTP 客户端实例
            
        Returns:
            所有绕过测试结果列表
        """
        logger.info(f"开始扫描接口认证绕过: {endpoint.method} {endpoint.path}")
        
        all_results = []
        
        token_results = self.test_token_bypass(endpoint, http_client)
        all_results.extend(token_results)
        
        method_results = self.test_method_bypass(endpoint, http_client)
        all_results.extend(method_results)
        
        header_results = self.test_header_bypass(endpoint, http_client)
        all_results.extend(header_results)
        
        bypass_count = sum(1 for r in all_results if r.get("bypass_success"))
        high_risk_count = sum(1 for r in all_results if r.get("risk_level") == "High")
        
        logger.info(
            f"接口扫描完成: {endpoint.method} {endpoint.path} - "
            f"共 {len(all_results)} 个测试，发现 {bypass_count} 个绕过，"
            f"其中 {high_risk_count} 个高危"
        )
        
        return all_results
    
    def scan_endpoints(
        self,
        endpoints: List[APIEndpoint],
        http_client: Optional[HttpClient] = None
    ) -> List[Dict]:
        """
        批量扫描接口的认证绕过漏洞
        
        对多个接口依次执行认证绕过扫描。
        
        Args:
            endpoints: API 接口列表
            http_client: HTTP 客户端实例（可选，不提供则使用初始化时的客户端）
            
        Returns:
            所有接口的绕过测试结果列表
        """
        client = http_client or self.http_client
        
        logger.info(f"开始批量扫描 {len(endpoints)} 个接口的认证绕过漏洞")
        
        all_results = []
        
        for idx, endpoint in enumerate(endpoints, 1):
            logger.info(f"扫描进度: {idx}/{len(endpoints)} - {endpoint.method} {endpoint.path}")
            
            try:
                results = self.scan_endpoint(endpoint, client)
                all_results.extend(results)
            except Exception as e:
                logger.error(f"扫描接口失败: {endpoint.method} {endpoint.path} - {e}")
                all_results.append({
                    "test_type": "scan_error",
                    "endpoint": f"{endpoint.method} {endpoint.path}",
                    "error": str(e),
                    "bypass_success": False,
                    "risk_level": "Unknown"
                })
        
        bypass_count = sum(1 for r in all_results if r.get("bypass_success"))
        high_risk_count = sum(1 for r in all_results if r.get("risk_level") == "High")
        
        logger.info(
            f"批量扫描完成 - 共 {len(endpoints)} 个接口，"
            f"{len(all_results)} 个测试，发现 {bypass_count} 个绕过，"
            f"其中 {high_risk_count} 个高危"
        )
        
        return all_results
    
    def _send_request(
        self,
        endpoint: APIEndpoint,
        http_client: HttpClient,
        headers: Dict[str, str]
    ) -> Optional[requests.Response]:
        """
        发送请求的辅助方法
        
        根据接口的 HTTP 方法发送对应的请求。
        
        Args:
            endpoint: API 接口对象
            http_client: HTTP 客户端实例
            headers: 请求头字典
            
        Returns:
            响应对象，失败返回 None
        """
        try:
            method = endpoint.method.upper()
            url = endpoint.url
            
            kwargs = {"headers": headers}
            
            if endpoint.parameters:
                body_params = {
                    p.name: p.default_value
                    for p in endpoint.parameters
                    if p.param_type == "body" and p.default_value is not None
                }
                if body_params:
                    kwargs["json"] = body_params
                
                query_params = {
                    p.name: p.default_value
                    for p in endpoint.parameters
                    if p.param_type == "query" and p.default_value is not None
                }
                if query_params:
                    kwargs["params"] = query_params
            
            if method == "GET":
                return http_client.get(url, **kwargs)
            elif method == "POST":
                return http_client.post(url, **kwargs)
            elif method == "PUT":
                return http_client.put(url, **kwargs)
            elif method == "DELETE":
                return http_client.delete(url, **kwargs)
            elif method == "PATCH":
                return http_client.patch(url, **kwargs)
            elif method == "HEAD":
                return http_client.head(url, **kwargs)
            elif method == "OPTIONS":
                return http_client.options(url, **kwargs)
            else:
                return http_client.request(method, url, **kwargs)
        
        except Exception as e:
            logger.error(f"发送请求失败: {endpoint.method} {endpoint.url} - {e}")
            return None
