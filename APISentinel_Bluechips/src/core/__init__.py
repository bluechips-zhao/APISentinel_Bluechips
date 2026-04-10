"""
核心模块

提供 API 安全扫描工具的核心数据模型和功能。
"""

from .models import (
    APIEndpoint,
    Parameter,
    TestResult,
    SensitiveInfo,
    Config,
    RequestChain,
    ChainStep,
    ExtractRule,
)
from .http_client import (
    HttpClient,
    HttpClientError,
    NetworkError,
    TimeoutError,
    SSLError,
    RetryExhaustedError,
)

__all__ = [
    "APIEndpoint",
    "Parameter",
    "TestResult",
    "SensitiveInfo",
    "Config",
    "RequestChain",
    "ChainStep",
    "ExtractRule",
    "HttpClient",
    "HttpClientError",
    "NetworkError",
    "TimeoutError",
    "SSLError",
    "RetryExhaustedError",
]
