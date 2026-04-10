"""
安全模式引擎

提供 API 接口的安全过滤功能，包括方法拦截、危险关键词过滤、黑名单管理等。
"""

import re
import logging
from typing import List, Optional, Set
from urllib.parse import urlparse

from ..core.models import APIEndpoint


logger = logging.getLogger(__name__)


class SafeMode:
    """安全模式引擎"""

    DEFAULT_BLOCKED_METHODS = ["DELETE", "PUT"]
    DEFAULT_DANGEROUS_KEYWORDS = [
        "delete", "remove", "drop", "truncate", 
        "destroy", "clear", "purge"
    ]

    def __init__(
        self,
        safe_mode: bool = True,
        blocked_methods: Optional[List[str]] = None,
        dangerous_keywords: Optional[List[str]] = None,
        blacklist: Optional[List[str]] = None
    ):
        """
        初始化安全模式引擎

        Args:
            safe_mode: 是否启用安全模式
            blocked_methods: 被拦截的方法列表
            dangerous_keywords: 危险关键词列表
            blacklist: URL 黑名单列表
        """
        self._safe_mode = safe_mode
        self._blocked_methods: Set[str] = set(
            method.upper() for method in (blocked_methods or self.DEFAULT_BLOCKED_METHODS)
        )
        self._dangerous_keywords: Set[str] = set(
            keyword.lower() for keyword in (dangerous_keywords or self.DEFAULT_DANGEROUS_KEYWORDS)
        )
        self._blacklist: List[str] = blacklist or []
        self._compiled_blacklist: List[re.Pattern] = []
        
        self._compile_blacklist_patterns()
        logger.info(
            f"SafeMode 初始化完成 - 安全模式: {self._safe_mode}, "
            f"拦截方法: {self._blocked_methods}, "
            f"危险关键词: {self._dangerous_keywords}, "
            f"黑名单数量: {len(self._blacklist)}"
        )

    def _compile_blacklist_patterns(self):
        """编译黑名单中的正则表达式"""
        self._compiled_blacklist = []
        for pattern in self._blacklist:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._compiled_blacklist.append(compiled)
                logger.debug(f"编译黑名单模式成功: {pattern}")
            except re.error as e:
                logger.warning(f"编译黑名单模式失败: {pattern}, 错误: {e}")

    def enable_safe_mode(self):
        """启用安全模式"""
        self._safe_mode = True
        logger.info("安全模式已启用")

    def disable_safe_mode(self):
        """禁用安全模式"""
        self._safe_mode = False
        logger.info("安全模式已禁用")

    def is_safe_mode_enabled(self) -> bool:
        """
        检查安全模式是否启用

        Returns:
            安全模式是否启用
        """
        return self._safe_mode

    def is_method_allowed(self, method: str) -> bool:
        """
        检查方法是否允许

        Args:
            method: HTTP 方法名称

        Returns:
            方法是否允许
        """
        if not self._safe_mode:
            return True

        method_upper = method.upper()
        is_allowed = method_upper not in self._blocked_methods
        
        if not is_allowed:
            logger.warning(f"方法被拦截: {method_upper}")
        
        return is_allowed

    def is_url_safe(self, url: str) -> bool:
        """
        检查 URL 是否安全

        Args:
            url: URL 字符串

        Returns:
            URL 是否安全
        """
        if not self._safe_mode:
            return True

        try:
            parsed = urlparse(url)
            path_lower = parsed.path.lower()
            
            for keyword in self._dangerous_keywords:
                if keyword in path_lower:
                    logger.warning(f"URL 包含危险关键词 '{keyword}': {url}")
                    return False
            
            return True
        except Exception as e:
            logger.error(f"URL 解析失败: {url}, 错误: {e}")
            return False

    def is_in_blacklist(self, url: str) -> bool:
        """
        检查 URL 是否在黑名单中

        Args:
            url: URL 字符串

        Returns:
            URL 是否在黑名单中
        """
        if not self._safe_mode:
            return False

        for pattern in self._compiled_blacklist:
            try:
                if pattern.search(url):
                    logger.warning(f"URL 匹配黑名单模式: {url}")
                    return True
            except Exception as e:
                logger.error(f"黑名单匹配异常: {e}")
        
        return False

    def add_to_blacklist(self, url_pattern: str):
        """
        添加 URL 模式到黑名单

        Args:
            url_pattern: URL 模式（支持正则表达式）
        """
        if url_pattern not in self._blacklist:
            self._blacklist.append(url_pattern)
            
            try:
                compiled = re.compile(url_pattern, re.IGNORECASE)
                self._compiled_blacklist.append(compiled)
                logger.info(f"添加黑名单模式: {url_pattern}")
            except re.error as e:
                logger.warning(f"添加黑名单模式失败: {url_pattern}, 错误: {e}")

    def remove_from_blacklist(self, url_pattern: str):
        """
        从黑名单移除 URL 模式

        Args:
            url_pattern: URL 模式
        """
        if url_pattern in self._blacklist:
            index = self._blacklist.index(url_pattern)
            self._blacklist.remove(url_pattern)
            
            if index < len(self._compiled_blacklist):
                self._compiled_blacklist.pop(index)
            
            logger.info(f"移除黑名单模式: {url_pattern}")

    def clear_blacklist(self):
        """清空黑名单"""
        self._blacklist.clear()
        self._compiled_blacklist.clear()
        logger.info("黑名单已清空")

    def get_blacklist(self) -> List[str]:
        """
        获取当前黑名单列表

        Returns:
            黑名单列表
        """
        return self._blacklist.copy()

    def is_endpoint_safe(self, endpoint: APIEndpoint) -> bool:
        """
        检查接口是否安全

        Args:
            endpoint: API 接口对象

        Returns:
            接口是否安全
        """
        if not self._safe_mode:
            return True

        if not self.is_method_allowed(endpoint.method):
            logger.warning(
                f"接口不安全 - 方法被拦截: {endpoint.method} {endpoint.url}"
            )
            return False

        if not self.is_url_safe(endpoint.url):
            logger.warning(
                f"接口不安全 - URL 包含危险关键词: {endpoint.url}"
            )
            return False

        if self.is_in_blacklist(endpoint.url):
            logger.warning(
                f"接口不安全 - URL 在黑名单中: {endpoint.url}"
            )
            return False

        logger.debug(f"接口安全: {endpoint.method} {endpoint.url}")
        return True

    def filter_endpoints(self, endpoints: List[APIEndpoint]) -> List[APIEndpoint]:
        """
        过滤不安全的接口

        Args:
            endpoints: API 接口列表

        Returns:
            过滤后的安全接口列表
        """
        if not self._safe_mode:
            logger.info("安全模式未启用，返回所有接口")
            return endpoints

        safe_endpoints = []
        unsafe_count = 0

        for endpoint in endpoints:
            if self.is_endpoint_safe(endpoint):
                safe_endpoints.append(endpoint)
            else:
                unsafe_count += 1

        logger.info(
            f"接口过滤完成 - 安全: {len(safe_endpoints)}, "
            f"不安全: {unsafe_count}, 总计: {len(endpoints)}"
        )
        
        return safe_endpoints

    def add_blocked_method(self, method: str):
        """
        添加被拦截的方法

        Args:
            method: HTTP 方法名称
        """
        method_upper = method.upper()
        self._blocked_methods.add(method_upper)
        logger.info(f"添加拦截方法: {method_upper}")

    def remove_blocked_method(self, method: str):
        """
        移除被拦截的方法

        Args:
            method: HTTP 方法名称
        """
        method_upper = method.upper()
        self._blocked_methods.discard(method_upper)
        logger.info(f"移除拦截方法: {method_upper}")

    def get_blocked_methods(self) -> List[str]:
        """
        获取被拦截的方法列表

        Returns:
            被拦截的方法列表
        """
        return list(self._blocked_methods)

    def add_dangerous_keyword(self, keyword: str):
        """
        添加危险关键词

        Args:
            keyword: 危险关键词
        """
        keyword_lower = keyword.lower()
        self._dangerous_keywords.add(keyword_lower)
        logger.info(f"添加危险关键词: {keyword_lower}")

    def remove_dangerous_keyword(self, keyword: str):
        """
        移除危险关键词

        Args:
            keyword: 危险关键词
        """
        keyword_lower = keyword.lower()
        self._dangerous_keywords.discard(keyword_lower)
        logger.info(f"移除危险关键词: {keyword_lower}")

    def get_dangerous_keywords(self) -> List[str]:
        """
        获取危险关键词列表

        Returns:
            危险关键词列表
        """
        return list(self._dangerous_keywords)

    def get_statistics(self) -> dict:
        """
        获取安全模式统计信息

        Returns:
            统计信息字典
        """
        return {
            "safe_mode": self._safe_mode,
            "blocked_methods_count": len(self._blocked_methods),
            "dangerous_keywords_count": len(self._dangerous_keywords),
            "blacklist_count": len(self._blacklist)
        }
