"""
批量测试执行器模块

本模块实现批量 API 测试执行功能，支持并发控制、超时重试、回调通知等特性。
集成敏感信息检测、JWT 检测、IDOR 检测、认证绕过检测等安全检测功能。
"""

import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Dict, List, Optional, Any

from ..core.http_client import HttpClient, HttpClientError
from ..core.models import APIEndpoint, TestResult
from .request_builder import RequestBuilder
from .sensitive_detector import SensitiveDetector
from .jwt_detector import JWTDetector
from .idor_detector import IDORDetector
from .auth_bypass import AuthBypassDetector
from .upload_detector import UploadDetector


logger = logging.getLogger(__name__)


class TestExecutor:
    """
    批量测试执行器
    
    提供批量 API 测试执行功能，支持并发控制、超时重试、进度跟踪和回调通知。
    
    Attributes:
        http_client: HTTP 客户端实例
        request_builder: 请求构造器实例
        timeout: 单个请求超时时间（秒）
        max_retries: 最大重试次数
        retry_delay: 重试延迟（秒）
    """
    
    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        verify_ssl: bool = True,
        request_builder: Optional[RequestBuilder] = None,
        enable_sensitive_detection: bool = True,
        enable_jwt_detection: bool = True,
        enable_idor_detection: bool = False,
        enable_auth_bypass_detection: bool = False,
        enable_upload_detection: bool = False,
    ):
        """
        初始化 TestExecutor
        
        Args:
            timeout: 单个请求超时时间（秒），默认 30 秒
            max_retries: 最大重试次数，默认 3 次
            retry_delay: 重试延迟（秒），默认 1 秒
            verify_ssl: 是否验证 SSL 证书，默认 True
            request_builder: 请求构造器实例（可选）
            enable_sensitive_detection: 是否启用敏感信息检测，默认 True
            enable_jwt_detection: 是否启用 JWT 检测，默认 True
            enable_idor_detection: 是否启用 IDOR 检测，默认 False
            enable_auth_bypass_detection: 是否启用认证绕过检测，默认 False
            enable_upload_detection: 是否启用上传漏洞检测，默认 False
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        self._http_client = HttpClient(
            timeout=timeout,
            max_retries=max_retries,
            retry_delay=retry_delay,
            verify_ssl=verify_ssl,
        )
        self._request_builder = request_builder or RequestBuilder()
        self._queue: List[APIEndpoint] = []
        
        self._on_test_start: Optional[Callable] = None
        self._on_test_complete: Optional[Callable] = None
        self._on_test_error: Optional[Callable] = None
        self._on_progress_update: Optional[Callable] = None
        self._progress_callback: Optional[Callable] = None
        
        self.enable_sensitive_detection = enable_sensitive_detection
        self.enable_jwt_detection = enable_jwt_detection
        self.enable_idor_detection = enable_idor_detection
        self.enable_auth_bypass_detection = enable_auth_bypass_detection
        self.enable_upload_detection = enable_upload_detection
        
        self._sensitive_detector = SensitiveDetector() if enable_sensitive_detection else None
        self._jwt_detector = JWTDetector() if enable_jwt_detection else None
        self._idor_detector = IDORDetector() if enable_idor_detection else None
        self._auth_bypass_detector = AuthBypassDetector(self._http_client) if enable_auth_bypass_detection else None
        self._upload_detector = UploadDetector(self._http_client) if enable_upload_detection else None
        
        logger.info(
            f"TestExecutor 初始化完成 - timeout={timeout}s, "
            f"max_retries={max_retries}, retry_delay={retry_delay}s, "
            f"敏感检测={enable_sensitive_detection}, JWT检测={enable_jwt_detection}, "
            f"IDOR检测={enable_idor_detection}, 认证绕过检测={enable_auth_bypass_detection}, "
            f"上传检测={enable_upload_detection}"
        )
    
    def add_endpoint(self, endpoint: APIEndpoint) -> None:
        """
        添加单个接口到队列
        
        Args:
            endpoint: API 接口对象
            
        Example:
            >>> executor = TestExecutor()
            >>> endpoint = APIEndpoint(url="https://api.example.com/users", method="GET", path="/users")
            >>> executor.add_endpoint(endpoint)
        """
        self._queue.append(endpoint)
        logger.debug(f"接口已添加到队列: {endpoint.method} {endpoint.path}, 当前队列大小: {len(self._queue)}")
    
    def add_endpoints(self, endpoints: List[APIEndpoint]) -> None:
        """
        添加多个接口到队列
        
        Args:
            endpoints: API 接口列表
            
        Example:
            >>> executor = TestExecutor()
            >>> endpoints = [
            ...     APIEndpoint(url="https://api.example.com/users", method="GET", path="/users"),
            ...     APIEndpoint(url="https://api.example.com/posts", method="GET", path="/posts")
            ... ]
            >>> executor.add_endpoints(endpoints)
        """
        self._queue.extend(endpoints)
        logger.info(f"已添加 {len(endpoints)} 个接口到队列，当前队列大小: {len(self._queue)}")
    
    def clear_queue(self) -> None:
        """
        清空队列
        
        移除队列中所有待测试的接口。
        """
        count = len(self._queue)
        self._queue.clear()
        logger.info(f"队列已清空，移除了 {count} 个接口")
    
    def get_queue_size(self) -> int:
        """
        获取队列大小
        
        Returns:
            当前队列中的接口数量
        """
        return len(self._queue)
    
    def get_pending_endpoints(self) -> List[APIEndpoint]:
        """
        获取待测试接口列表
        
        Returns:
            当前队列中的所有接口列表（副本）
        """
        return list(self._queue)
    
    def set_progress_callback(self, callback: Callable) -> None:
        """
        设置进度回调函数
        
        Args:
            callback: 回调函数，签名为 callback(completed: int, total: int, result: TestResult)
        """
        self._progress_callback = callback
        logger.debug("进度回调函数已设置")
    
    def on_test_start(self, callback: Callable) -> None:
        """
        设置测试开始回调
        
        Args:
            callback: 回调函数，签名为 callback(endpoint: APIEndpoint)
        """
        self._on_test_start = callback
        logger.debug("测试开始回调已设置")
    
    def on_test_complete(self, callback: Callable) -> None:
        """
        设置测试完成回调
        
        Args:
            callback: 回调函数，签名为 callback(result: TestResult)
        """
        self._on_test_complete = callback
        logger.debug("测试完成回调已设置")
    
    def on_test_error(self, callback: Callable) -> None:
        """
        设置测试错误回调
        
        Args:
            callback: 回调函数，签名为 callback(endpoint: APIEndpoint, error: Exception)
        """
        self._on_test_error = callback
        logger.debug("测试错误回调已设置")
    
    def on_progress_update(self, callback: Callable) -> None:
        """
        设置进度更新回调
        
        Args:
            callback: 回调函数，签名为 callback(completed: int, total: int, result: TestResult)
        """
        self._on_progress_update = callback
        logger.debug("进度更新回调已设置")
    
    def execute_endpoint(self, endpoint: APIEndpoint, request_format: str = "auto") -> TestResult:
        """
        执行单个接口测试
        
        使用 RequestBuilder 构造请求，使用 HttpClient 发送请求，记录响应信息。
        
        Args:
            endpoint: API 接口对象
            request_format: 请求格式（"auto"/"query"/"json"/"form"）
            
        Returns:
            TestResult 对象
            
        Example:
            >>> executor = TestExecutor()
            >>> endpoint = APIEndpoint(url="https://api.example.com/users", method="GET", path="/users")
            >>> result = executor.execute_endpoint(endpoint)
        """
        request_id = str(uuid.uuid4())
        logger.info(f"开始执行测试: {endpoint.method} {endpoint.path}, request_id={request_id}")
        
        if self._on_test_start:
            try:
                self._on_test_start(endpoint)
            except Exception as e:
                logger.error(f"测试开始回调执行失败: {e}")
        
        request_data = self._request_builder.build_request(endpoint, format=request_format)
        
        request_headers = request_data["headers"]
        request_body = request_data["body"]
        
        start_time = time.time()
        error_msg = ""
        response_status = 0
        response_headers: Dict[str, str] = {}
        response_body = ""
        response_length = 0
        
        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug(f"[尝试 {attempt}/{self.max_retries}] 发送请求: {endpoint.method} {request_data['url']}")
                
                kwargs = {
                    "headers": request_headers,
                    "timeout": self.timeout,
                }
                
                if request_body:
                    if request_headers.get("Content-Type") == "application/json":
                        kwargs["data"] = request_body
                    elif request_headers.get("Content-Type") == "application/x-www-form-urlencoded":
                        kwargs["data"] = request_body
                    else:
                        kwargs["data"] = request_body
                
                response = self._http_client.request(
                    method=request_data["method"],
                    url=request_data["url"],
                    **kwargs
                )
                
                response_status = response.status_code
                response_headers = dict(response.headers)
                response_body = response.text
                response_length = len(response.content)
                
                logger.info(
                    f"请求成功: {endpoint.method} {endpoint.path} - "
                    f"状态码: {response_status}, 响应大小: {response_length} 字节"
                )
                
                break
                
            except HttpClientError as e:
                error_msg = str(e)
                logger.warning(
                    f"[尝试 {attempt}/{self.max_retries}] 请求失败: {endpoint.method} {endpoint.path} - {error_msg}"
                )
                
                if attempt < self.max_retries:
                    logger.info(f"{self.retry_delay} 秒后重试...")
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"重试耗尽: {endpoint.method} {endpoint.path}")
                    if self._on_test_error:
                        try:
                            self._on_test_error(endpoint, e)
                        except Exception as callback_error:
                            logger.error(f"测试错误回调执行失败: {callback_error}")
            
            except Exception as e:
                error_msg = str(e)
                logger.error(f"未预期的错误: {endpoint.method} {endpoint.path} - {error_msg}")
                if self._on_test_error:
                    try:
                        self._on_test_error(endpoint, e)
                    except Exception as callback_error:
                        logger.error(f"测试错误回调执行失败: {callback_error}")
                break
        
        end_time = time.time()
        response_time = end_time - start_time
        
        sensitive_info = []
        jwt_info = []
        idor_info = {}
        auth_bypass_info = []
        upload_info = []
        
        if self._sensitive_detector and response_body:
            try:
                sensitive_info = self._sensitive_detector.detect_in_response(
                    response_body, response_headers
                )
                logger.debug(f"敏感信息检测完成: 发现 {len(sensitive_info)} 个敏感信息")
            except Exception as e:
                logger.error(f"敏感信息检测失败: {e}")
        
        if self._jwt_detector and response_body:
            try:
                jwt_info = self._jwt_detector.scan_response(response_body, response_headers)
                if jwt_info:
                    logger.debug(f"JWT 检测完成: 发现 {len(jwt_info)} 个 JWT")
            except Exception as e:
                logger.error(f"JWT 检测失败: {e}")
        
        if self._idor_detector:
            try:
                idor_info = self._idor_detector.detect_idor(endpoint, self._http_client)
                if idor_info.get("is_vulnerable"):
                    logger.warning(f"IDOR 漏洞检测: {endpoint.method} {endpoint.path} - 存在漏洞")
            except Exception as e:
                logger.error(f"IDOR 检测失败: {e}")
        
        if self._auth_bypass_detector:
            try:
                auth_bypass_info = self._auth_bypass_detector.scan_endpoint(endpoint, self._http_client)
                bypass_count = sum(1 for r in auth_bypass_info if r.get("bypass_success"))
                if bypass_count > 0:
                    logger.warning(f"认证绕过检测: {endpoint.method} {endpoint.path} - 发现 {bypass_count} 个绕过")
            except Exception as e:
                logger.error(f"认证绕过检测失败: {e}")
        
        if self._upload_detector:
            try:
                is_upload = self._upload_detector.detect_upload_endpoint(endpoint)
                if is_upload:
                    upload_info = self._upload_detector.test_upload(endpoint)
                    if upload_info.get("vulnerability"):
                        logger.warning(f"上传漏洞检测: {endpoint.method} {endpoint.path} - 存在漏洞")
            except Exception as e:
                logger.error(f"上传漏洞检测失败: {e}")
        
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
            sensitive_info=sensitive_info,
            jwt_info=jwt_info,
            idor_info=idor_info,
            auth_bypass_info=auth_bypass_info,
            upload_info=upload_info,
            timestamp=datetime.now(),
            error=error_msg,
        )
        
        if self._on_test_complete:
            try:
                self._on_test_complete(result)
            except Exception as e:
                logger.error(f"测试完成回调执行失败: {e}")
        
        logger.info(
            f"测试完成: {endpoint.method} {endpoint.path} - "
            f"响应时间: {response_time:.2f}s, 状态码: {response_status}"
        )
        
        return result
    
    def execute_one(self, endpoint: APIEndpoint) -> TestResult:
        """
        执行单个测试（简化接口）
        
        Args:
            endpoint: API 接口对象
            
        Returns:
            TestResult 对象
        """
        return self.execute_endpoint(endpoint)
    
    def execute_all(self, max_workers: int = 10) -> List[TestResult]:
        """
        并发执行所有测试
        
        使用 ThreadPoolExecutor 实现并发执行，支持进度跟踪和回调通知。
        
        Args:
            max_workers: 最大并发数，默认 10
            
        Returns:
            TestResult 列表
            
        Example:
            >>> executor = TestExecutor()
            >>> executor.add_endpoints([endpoint1, endpoint2, endpoint3])
            >>> results = executor.execute_all(max_workers=5)
        """
        total = len(self._queue)
        
        if total == 0:
            logger.warning("队列为空，没有需要执行的测试")
            return []
        
        logger.info(f"开始并发执行 {total} 个测试，最大并发数: {max_workers}")
        
        results: List[TestResult] = []
        completed = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_endpoint = {
                executor.submit(self.execute_endpoint, endpoint): endpoint
                for endpoint in self._queue
            }
            
            for future in as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    completed += 1
                    
                    if self._progress_callback:
                        try:
                            self._progress_callback(completed, total, result)
                        except Exception as e:
                            logger.error(f"进度回调执行失败: {e}")
                    
                    if self._on_progress_update:
                        try:
                            self._on_progress_update(completed, total, result)
                        except Exception as e:
                            logger.error(f"进度更新回调执行失败: {e}")
                    
                    logger.debug(f"进度: {completed}/{total} - {endpoint.method} {endpoint.path}")
                    
                except Exception as e:
                    logger.error(f"测试执行异常: {endpoint.method} {endpoint.path} - {e}")
                    
                    error_result = TestResult(
                        request_id=str(uuid.uuid4()),
                        endpoint=endpoint,
                        request_headers={},
                        request_body="",
                        response_status=0,
                        response_headers={},
                        response_body="",
                        response_length=0,
                        response_time=0.0,
                        sensitive_info=[],
                        timestamp=datetime.now(),
                        error=str(e),
                    )
                    results.append(error_result)
                    
                    completed += 1
                    
                    if self._progress_callback:
                        try:
                            self._progress_callback(completed, total, error_result)
                        except Exception as callback_error:
                            logger.error(f"进度回调执行失败: {callback_error}")
                    
                    if self._on_progress_update:
                        try:
                            self._on_progress_update(completed, total, error_result)
                        except Exception as callback_error:
                            logger.error(f"进度更新回调执行失败: {callback_error}")
        
        logger.info(f"所有测试执行完成: {len(results)}/{total}")
        
        return results
    
    def set_proxy(self, proxy: str) -> None:
        """
        设置代理
        
        Args:
            proxy: 代理地址
        """
        self._http_client.set_proxy(proxy)
        logger.info(f"TestExecutor 代理已设置: {proxy}")
    
    def clear_proxy(self) -> None:
        """
        清除代理设置
        """
        self._http_client.clear_proxy()
        logger.info("TestExecutor 代理已清除")
    
    def set_default_headers(self, headers: Dict[str, str]) -> None:
        """
        设置默认请求头
        
        Args:
            headers: 请求头字典
        """
        self._http_client.set_default_headers(headers)
        logger.info(f"TestExecutor 默认请求头已设置: {list(headers.keys())}")
    
    def close(self) -> None:
        """
        关闭执行器
        
        关闭 HTTP 客户端并释放资源。
        """
        self._http_client.close()
        logger.info("TestExecutor 已关闭")
    
    def __enter__(self) -> "TestExecutor":
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """上下文管理器出口"""
        self.close()
    
    def get_statistics(self) -> Dict[str, any]:
        """
        获取执行统计信息
        
        Returns:
            包含统计信息的字典
        """
        return {
            "queue_size": len(self._queue),
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "http_client_info": self._http_client.get_session_info(),
        }
