"""
HTTP 客户端模块

本模块实现核心 HTTP 请求功能，支持代理、自定义请求头、文件上传等特性。
"""

import logging
import mimetypes
import os
import time
from typing import Any, Dict, Optional, Tuple, Union
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logger = logging.getLogger(__name__)


class HttpClientError(Exception):
    """HTTP 客户端异常基类"""
    pass


class NetworkError(HttpClientError):
    """网络连接异常"""
    pass


class TimeoutError(HttpClientError):
    """请求超时异常"""
    pass


class SSLError(HttpClientError):
    """SSL 证书异常"""
    pass


class RetryExhaustedError(HttpClientError):
    """重试耗尽异常"""
    pass


class HttpClient:
    """
    HTTP 客户端类
    
    提供完整的 HTTP 请求功能，包括代理支持、自定义请求头、文件上传、重试机制等。
    
    Attributes:
        timeout: 请求超时时间（秒）
        max_retries: 最大重试次数
        retry_delay: 重试延迟（秒）
        verify_ssl: 是否验证 SSL 证书
        session: requests Session 对象
    """
    
    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        verify_ssl: bool = True,
    ):
        """
        初始化 HttpClient
        
        Args:
            timeout: 请求超时时间（秒），默认 30 秒
            max_retries: 最大重试次数，默认 3 次
            retry_delay: 重试延迟（秒），默认 1 秒
            verify_ssl: 是否验证 SSL 证书，默认 True
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.verify_ssl = verify_ssl
        
        self._session = requests.Session()
        self._default_headers: Dict[str, str] = {}
        self._proxy: Optional[Dict[str, str]] = None
        
        self._setup_retry_adapter()
        logger.info(
            f"HttpClient 初始化完成 - timeout={timeout}s, "
            f"max_retries={max_retries}, verify_ssl={verify_ssl}"
        )
    
    def _setup_retry_adapter(self) -> None:
        """
        设置重试适配器
        
        为 Session 配置自动重试机制，处理连接错误和特定状态码。
        """
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.retry_delay,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)
        logger.debug("重试适配器配置完成")
    
    def set_proxy(self, proxy: str) -> None:
        """
        设置代理
        
        支持 HTTP、HTTPS 和 SOCKS5 代理。
        
        Args:
            proxy: 代理地址
                - HTTP: http://127.0.0.1:8080
                - HTTPS: https://127.0.0.1:8080
                - SOCKS5: socks5://127.0.0.1:1080
                
        Example:
            >>> client = HttpClient()
            >>> client.set_proxy("http://127.0.0.1:8080")
            >>> client.set_proxy("socks5://127.0.0.1:1080")
        """
        if not proxy:
            logger.warning("代理地址为空，跳过设置")
            return
        
        self._proxy = {
            "http": proxy,
            "https": proxy,
        }
        
        self._session.proxies = self._proxy
        logger.info(f"代理已设置: {proxy}")
    
    def clear_proxy(self) -> None:
        """
        清除代理设置
        
        移除当前所有代理配置。
        """
        self._proxy = None
        self._session.proxies = {}
        logger.info("代理已清除")
    
    def set_default_headers(self, headers: Dict[str, str]) -> None:
        """
        设置默认请求头
        
        设置的请求头将应用到所有后续请求中。
        
        Args:
            headers: 请求头字典
            
        Example:
            >>> client = HttpClient()
            >>> client.set_default_headers({
            ...     "User-Agent": "MyApp/1.0",
            ...     "Authorization": "Bearer token123"
            ... })
        """
        self._default_headers.update(headers)
        self._session.headers.update(headers)
        logger.info(f"默认请求头已设置: {list(headers.keys())}")
    
    def add_header(self, key: str, value: str) -> None:
        """
        添加单个请求头
        
        Args:
            key: 请求头名称
            value: 请求头值
            
        Example:
            >>> client = HttpClient()
            >>> client.add_header("Authorization", "Bearer token123")
        """
        self._default_headers[key] = value
        self._session.headers[key] = value
        logger.debug(f"请求头已添加: {key}")
    
    def remove_header(self, key: str) -> None:
        """
        移除请求头
        
        Args:
            key: 要移除的请求头名称
            
        Example:
            >>> client = HttpClient()
            >>> client.remove_header("Authorization")
        """
        if key in self._default_headers:
            del self._default_headers[key]
        if key in self._session.headers:
            del self._session.headers[key]
        logger.debug(f"请求头已移除: {key}")
    
    def _merge_headers(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        合并请求头
        
        将默认请求头与请求特定的请求头合并。
        
        Args:
            headers: 请求特定的请求头
            
        Returns:
            合并后的请求头字典
        """
        merged = dict(self._default_headers)
        if headers:
            merged.update(headers)
        return merged
    
    def _handle_request_error(self, error: Exception, attempt: int, url: str) -> None:
        """
        处理请求错误
        
        根据错误类型进行分类处理，并记录日志。
        
        Args:
            error: 异常对象
            attempt: 当前尝试次数
            url: 请求 URL
            
        Raises:
            对应的自定义异常
        """
        if isinstance(error, requests.exceptions.ConnectionError):
            logger.error(f"[尝试 {attempt}] 网络连接失败: {url} - {error}")
            raise NetworkError(f"网络连接失败: {error}")
        elif isinstance(error, requests.exceptions.Timeout):
            logger.error(f"[尝试 {attempt}] 请求超时: {url} - {error}")
            raise TimeoutError(f"请求超时: {error}")
        elif isinstance(error, requests.exceptions.SSLError):
            logger.error(f"[尝试 {attempt}] SSL 证书错误: {url} - {error}")
            raise SSLError(f"SSL 证书错误: {error}")
        else:
            logger.error(f"[尝试 {attempt}] 请求失败: {url} - {error}")
            raise HttpClientError(f"请求失败: {error}")
    
    def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> requests.Response:
        """
        发送 HTTP 请求
        
        核心请求方法，支持重试机制和完整的错误处理。
        
        Args:
            method: HTTP 方法（GET/POST/PUT/DELETE/PATCH 等）
            url: 请求 URL
            **kwargs: 额外参数
                - timeout: 超时时间（覆盖默认值）
                - verify: 是否验证 SSL（覆盖默认值）
                - allow_redirects: 是否允许重定向
                - headers: 请求头
                - params: Query 参数
                - data: 请求体数据
                - json: JSON 请求体
                
        Returns:
            requests.Response 对象
            
        Raises:
            NetworkError: 网络连接失败
            TimeoutError: 请求超时
            SSLError: SSL 证书错误
            RetryExhaustedError: 重试耗尽
            
        Example:
            >>> client = HttpClient()
            >>> response = client.request("GET", "https://api.example.com/users")
        """
        timeout = kwargs.pop("timeout", self.timeout)
        verify = kwargs.pop("verify", self.verify_ssl)
        allow_redirects = kwargs.pop("allow_redirects", True)
        headers = self._merge_headers(kwargs.pop("headers", None))
        
        kwargs["timeout"] = timeout
        kwargs["verify"] = verify
        kwargs["allow_redirects"] = allow_redirects
        kwargs["headers"] = headers
        
        last_error: Optional[Exception] = None
        
        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(f"[尝试 {attempt}/{self.max_retries}] {method} {url}")
                
                response = self._session.request(method, url, **kwargs)
                
                logger.info(
                    f"请求成功: {method} {url} - "
                    f"状态码: {response.status_code}, "
                    f"响应大小: {len(response.content)} 字节"
                )
                
                return response
                
            except requests.exceptions.RequestException as e:
                last_error = e
                
                if attempt < self.max_retries:
                    logger.warning(
                        f"[尝试 {attempt}/{self.max_retries}] 请求失败，"
                        f"{self.retry_delay} 秒后重试: {url}"
                    )
                    time.sleep(self.retry_delay)
                else:
                    self._handle_request_error(e, attempt, url)
        
        raise RetryExhaustedError(f"重试耗尽: {last_error}")
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """
        发送 GET 请求
        
        Args:
            url: 请求 URL
            **kwargs: 额外参数（参见 request 方法）
            
        Returns:
            requests.Response 对象
            
        Example:
            >>> client = HttpClient()
            >>> response = client.get("https://api.example.com/users")
        """
        return self.request("GET", url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """
        发送 POST 请求
        
        Args:
            url: 请求 URL
            **kwargs: 额外参数（参见 request 方法）
            
        Returns:
            requests.Response 对象
            
        Example:
            >>> client = HttpClient()
            >>> response = client.post(
            ...     "https://api.example.com/users",
            ...     json={"name": "test"}
            ... )
        """
        return self.request("POST", url, **kwargs)
    
    def put(self, url: str, **kwargs) -> requests.Response:
        """
        发送 PUT 请求
        
        Args:
            url: 请求 URL
            **kwargs: 额外参数（参见 request 方法）
            
        Returns:
            requests.Response 对象
            
        Example:
            >>> client = HttpClient()
            >>> response = client.put(
            ...     "https://api.example.com/users/1",
            ...     json={"name": "updated"}
            ... )
        """
        return self.request("PUT", url, **kwargs)
    
    def delete(self, url: str, **kwargs) -> requests.Response:
        """
        发送 DELETE 请求
        
        Args:
            url: 请求 URL
            **kwargs: 额外参数（参见 request 方法）
            
        Returns:
            requests.Response 对象
            
        Example:
            >>> client = HttpClient()
            >>> response = client.delete("https://api.example.com/users/1")
        """
        return self.request("DELETE", url, **kwargs)
    
    def patch(self, url: str, **kwargs) -> requests.Response:
        """
        发送 PATCH 请求
        
        Args:
            url: 请求 URL
            **kwargs: 额外参数（参见 request 方法）
            
        Returns:
            requests.Response 对象
            
        Example:
            >>> client = HttpClient()
            >>> response = client.patch(
            ...     "https://api.example.com/users/1",
            ...     json={"name": "patched"}
            ... )
        """
        return self.request("PATCH", url, **kwargs)
    
    def head(self, url: str, **kwargs) -> requests.Response:
        """
        发送 HEAD 请求
        
        Args:
            url: 请求 URL
            **kwargs: 额外参数（参见 request 方法）
            
        Returns:
            requests.Response 对象
        """
        return self.request("HEAD", url, **kwargs)
    
    def options(self, url: str, **kwargs) -> requests.Response:
        """
        发送 OPTIONS 请求
        
        Args:
            url: 请求 URL
            **kwargs: 额外参数（参见 request 方法）
            
        Returns:
            requests.Response 对象
        """
        return self.request("OPTIONS", url, **kwargs)
    
    def _detect_mime_type(self, file_path: str) -> str:
        """
        检测文件的 MIME 类型
        
        Args:
            file_path: 文件路径
            
        Returns:
            MIME 类型字符串
        """
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type or "application/octet-stream"
    
    def _prepare_file_tuple(
        self,
        file_path: str,
        field_name: str,
        filename: Optional[str] = None,
        mime_type: Optional[str] = None,
    ) -> Tuple[str, Tuple[str, Any, str]]:
        """
        准备文件上传元组
        
        Args:
            file_path: 文件路径
            field_name: 表单字段名
            filename: 自定义文件名
            mime_type: 自定义 MIME 类型
            
        Returns:
            (field_name, (filename, file_object, mime_type)) 元组
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        actual_filename = filename or path.name
        actual_mime_type = mime_type or self._detect_mime_type(file_path)
        
        file_obj = open(path, "rb")
        
        return (field_name, (actual_filename, file_obj, actual_mime_type))
    
    def upload_file(
        self,
        url: str,
        file_path: str,
        field_name: str = "file",
        filename: Optional[str] = None,
        mime_type: Optional[str] = None,
        **kwargs
    ) -> requests.Response:
        """
        上传单个文件
        
        使用 multipart/form-data 格式上传单个文件。
        
        Args:
            url: 上传目标 URL
            file_path: 文件路径
            field_name: 表单字段名，默认 "file"
            filename: 自定义文件名（可选）
            mime_type: 自定义 MIME 类型（可选）
            **kwargs: 额外参数
                - data: 额外的表单字段
                - headers: 额外的请求头
                
        Returns:
            requests.Response 对象
            
        Raises:
            FileNotFoundError: 文件不存在
            
        Example:
            >>> client = HttpClient()
            >>> response = client.upload_file(
            ...     "https://api.example.com/upload",
            ...     "/path/to/file.txt"
            ... )
            >>> response = client.upload_file(
            ...     "https://api.example.com/upload",
            ...     "/path/to/file.txt",
            ...     field_name="document",
            ...     filename="custom_name.txt",
            ...     mime_type="text/plain"
            ... )
        """
        logger.info(f"准备上传文件: {file_path} -> {url}")
        
        file_tuple = self._prepare_file_tuple(file_path, field_name, filename, mime_type)
        files = {file_tuple[0]: file_tuple[1]}
        
        try:
            response = self.request("POST", url, files=files, **kwargs)
            logger.info(f"文件上传成功: {file_path}")
            return response
        finally:
            if isinstance(file_tuple[1][1], object) and hasattr(file_tuple[1][1], "close"):
                file_tuple[1][1].close()
    
    def upload_files(
        self,
        url: str,
        files: Dict[str, str],
        filenames: Optional[Dict[str, str]] = None,
        mime_types: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> requests.Response:
        """
        上传多个文件
        
        使用 multipart/form-data 格式同时上传多个文件。
        
        Args:
            url: 上传目标 URL
            files: 文件字典 {字段名: 文件路径}
            filenames: 自定义文件名字典 {字段名: 文件名}（可选）
            mime_types: 自定义 MIME 类型字典 {字段名: MIME 类型}（可选）
            **kwargs: 额外参数
                - data: 额外的表单字段
                - headers: 额外的请求头
                
        Returns:
            requests.Response 对象
            
        Raises:
            FileNotFoundError: 文件不存在
            
        Example:
            >>> client = HttpClient()
            >>> response = client.upload_files(
            ...     "https://api.example.com/upload",
            ...     {
            ...         "file1": "/path/to/file1.txt",
            ...         "file2": "/path/to/file2.pdf"
            ...     }
            ... )
        """
        logger.info(f"准备上传 {len(files)} 个文件到 {url}")
        
        filenames = filenames or {}
        mime_types = mime_types or {}
        
        prepared_files = {}
        file_handles = []
        
        try:
            for field_name, file_path in files.items():
                custom_filename = filenames.get(field_name)
                custom_mime = mime_types.get(field_name)
                
                file_tuple = self._prepare_file_tuple(
                    file_path, field_name, custom_filename, custom_mime
                )
                prepared_files[file_tuple[0]] = file_tuple[1]
                file_handles.append(file_tuple[1][1])
            
            response = self.request("POST", url, files=prepared_files, **kwargs)
            logger.info(f"多文件上传成功: {len(files)} 个文件")
            return response
        finally:
            for handle in file_handles:
                if hasattr(handle, "close"):
                    handle.close()
    
    def close(self) -> None:
        """
        关闭客户端
        
        关闭 Session 并释放资源。
        """
        self._session.close()
        logger.info("HttpClient 已关闭")
    
    def __enter__(self) -> "HttpClient":
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """上下文管理器出口"""
        self.close()
    
    @property
    def cookies(self) -> requests.cookies.RequestsCookieJar:
        """
        获取当前 Cookie
        
        Returns:
            Cookie Jar 对象
        """
        return self._session.cookies
    
    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """
        设置 Cookie
        
        Args:
            cookies: Cookie 字典
            
        Example:
            >>> client = HttpClient()
            >>> client.set_cookies({"session_id": "abc123", "user_token": "xyz789"})
        """
        for name, value in cookies.items():
            self._session.cookies.set(name, value)
        logger.debug(f"Cookie 已设置: {list(cookies.keys())}")
    
    def clear_cookies(self) -> None:
        """清除所有 Cookie"""
        self._session.cookies.clear()
        logger.debug("Cookie 已清除")
    
    def get_session_info(self) -> Dict[str, Any]:
        """
        获取当前会话信息
        
        Returns:
            包含会话配置信息的字典
        """
        return {
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "verify_ssl": self.verify_ssl,
            "proxy": self._proxy,
            "default_headers": dict(self._default_headers),
            "cookies_count": len(self._session.cookies),
        }
