"""
敏感信息检测引擎

提供文本、响应头、Cookie 等多种来源的敏感信息检测功能。
支持正则匹配、等级分类、高亮标记等功能。
"""

import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from functools import lru_cache

from ..core.models import SensitiveInfo
from .sensitive_rules import SensitiveRuleLibrary, sensitive_rule_library


logger = logging.getLogger(__name__)


class SensitiveDetector:
    """敏感信息检测引擎"""

    LEVEL_COLORS = {
        "High": "#FF0000",
        "Medium": "#FFA500",
        "Low": "#FFFF00"
    }

    def __init__(self, rule_library: Optional[SensitiveRuleLibrary] = None, max_workers: int = 4):
        """
        初始化敏感信息检测引擎

        Args:
            rule_library: 规则库实例，为 None 则使用默认规则库
            max_workers: 并行检测的最大线程数
        """
        self.rule_library = rule_library or sensitive_rule_library
        self.max_workers = max_workers
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._compile_all_patterns()
        logger.info(f"SensitiveDetector 初始化完成，规则数量: {len(self.rule_library)}")

    def _compile_all_patterns(self):
        """编译所有规则的正则表达式"""
        for rule in self.rule_library.get_rules():
            try:
                pattern = re.compile(rule["pattern"])
                self._compiled_patterns[rule["name"]] = pattern
                logger.debug(f"编译规则成功: {rule['name']}")
            except re.error as e:
                logger.warning(f"编译规则失败: {rule['name']}, 错误: {e}")

    @lru_cache(maxsize=128)
    def _get_compiled_pattern(self, pattern_str: str) -> Optional[re.Pattern]:
        """
        获取编译后的正则表达式（带缓存）

        Args:
            pattern_str: 正则表达式字符串

        Returns:
            编译后的正则表达式对象，失败返回 None
        """
        try:
            return re.compile(pattern_str)
        except re.error as e:
            logger.warning(f"编译正则表达式失败: {pattern_str}, 错误: {e}")
            return None

    def _detect_with_rule(self, text: str, rule: Dict) -> List[SensitiveInfo]:
        """
        使用单个规则检测文本

        Args:
            text: 待检测文本
            rule: 规则字典

        Returns:
            检测到的敏感信息列表
        """
        results = []
        pattern = self._compiled_patterns.get(rule["name"])
        
        if not pattern:
            return results

        try:
            for match in pattern.finditer(text):
                sensitive_info = SensitiveInfo(
                    rule_name=rule["name"],
                    rule_level=rule["level"],
                    pattern=rule["pattern"],
                    matched_content=match.group(),
                    position=(match.start(), match.end())
                )
                results.append(sensitive_info)
                logger.debug(
                    f"检测到敏感信息: {rule['name']}, "
                    f"等级: {rule['level']}, "
                    f"位置: {match.start()}-{match.end()}"
                )
        except Exception as e:
            logger.error(f"规则检测异常: {rule['name']}, 错误: {e}")

        return results

    def detect(self, text: str, categories: Optional[List[str]] = None) -> List[SensitiveInfo]:
        """
        检测文本中的敏感信息

        Args:
            text: 待检测文本
            categories: 要检测的规则分类列表，为 None 则检测所有

        Returns:
            SensitiveInfo 对象列表
        """
        if not text:
            return []

        all_results = []
        rules = self.rule_library.get_rules()
        
        if categories:
            rules = [r for r in rules if r.get("category") in categories]

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._detect_with_rule, text, rule): rule
                for rule in rules
            }

            for future in as_completed(futures):
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    rule = futures[future]
                    logger.error(f"并行检测异常: {rule['name']}, 错误: {e}")

        all_results.sort(key=lambda x: x.position[0])
        logger.info(f"检测完成，发现 {len(all_results)} 个敏感信息")
        return all_results

    def filter_by_level(self, sensitive_info_list: List[SensitiveInfo], level: str) -> List[SensitiveInfo]:
        """
        过滤指定等级的敏感信息

        Args:
            sensitive_info_list: 敏感信息列表
            level: 敏感等级（High/Medium/Low）

        Returns:
            过滤后的敏感信息列表
        """
        if level not in ["High", "Medium", "Low"]:
            logger.warning(f"无效的敏感等级: {level}")
            return []

        filtered = [info for info in sensitive_info_list if info.rule_level == level]
        logger.info(f"过滤等级 {level}，共 {len(filtered)} 个结果")
        return filtered

    def highlight_text(
        self,
        text: str,
        sensitive_info_list: List[SensitiveInfo],
        use_html: bool = True
    ) -> str:
        """
        高亮敏感信息

        Args:
            text: 原始文本
            sensitive_info_list: 敏感信息列表
            use_html: 是否使用 HTML 标签，False 则使用特殊字符标记

        Returns:
            高亮后的文本
        """
        if not sensitive_info_list:
            return text

        sorted_info = sorted(sensitive_info_list, key=lambda x: x.position[0], reverse=True)
        
        result = text
        for info in sorted_info:
            start, end = info.position
            if start < 0 or end > len(result) or start >= end:
                continue

            color = self.LEVEL_COLORS.get(info.rule_level, "#FFFF00")
            matched_text = result[start:end]

            if use_html:
                highlighted = f'<span style="background-color: {color}; color: #000000; font-weight: bold;">{matched_text}</span>'
            else:
                highlighted = f"【{info.rule_level}】{matched_text}【/{info.rule_level}】"

            result = result[:start] + highlighted + result[end:]

        logger.info(f"高亮处理完成，处理了 {len(sensitive_info_list)} 个敏感信息")
        return result

    def detect_in_response(
        self,
        response_body: str,
        response_headers: Optional[Dict[str, str]] = None
    ) -> List[SensitiveInfo]:
        """
        检测响应中的敏感信息

        Args:
            response_body: 响应体内容
            response_headers: 响应头字典

        Returns:
            检测到的敏感信息列表
        """
        all_results = []

        if response_body:
            body_results = self.detect(response_body)
            all_results.extend(body_results)
            logger.debug(f"响应体检测完成，发现 {len(body_results)} 个敏感信息")

        if response_headers:
            header_results = self.detect_in_headers(response_headers)
            all_results.extend(header_results)
            logger.debug(f"响应头检测完成，发现 {len(header_results)} 个敏感信息")

        logger.info(f"响应检测完成，共发现 {len(all_results)} 个敏感信息")
        return all_results

    def detect_in_headers(self, headers: Dict[str, str]) -> List[SensitiveInfo]:
        """
        检测请求头中的敏感信息

        Args:
            headers: 请求头字典

        Returns:
            检测到的敏感信息列表
        """
        all_results = []

        for header_name, header_value in headers.items():
            header_text = f"{header_name}: {header_value}"
            results = self.detect(header_text)
            
            for result in results:
                result.position = (
                    result.position[0] - len(header_name) - 2,
                    result.position[1] - len(header_name) - 2
                )
                all_results.append(result)

        logger.info(f"请求头检测完成，发现 {len(all_results)} 个敏感信息")
        return all_results

    def detect_in_cookies(self, cookies: str) -> List[SensitiveInfo]:
        """
        检测 Cookie 中的敏感信息

        Args:
            cookies: Cookie 字符串

        Returns:
            检测到的敏感信息列表
        """
        if not cookies:
            return []

        all_results = []
        cookie_pairs = cookies.split(';')

        for cookie_pair in cookie_pairs:
            cookie_pair = cookie_pair.strip()
            if '=' in cookie_pair:
                name, value = cookie_pair.split('=', 1)
                cookie_text = f"{name.strip()}={value.strip()}"
                results = self.detect(cookie_text)
                
                for result in results:
                    result.position = (
                        result.position[0] - len(name) - 1,
                        result.position[1] - len(name) - 1
                    )
                    all_results.append(result)

        logger.info(f"Cookie 检测完成，发现 {len(all_results)} 个敏感信息")
        return all_results

    def get_statistics(self, sensitive_info_list: List[SensitiveInfo]) -> Dict[str, int]:
        """
        获取敏感信息统计信息

        Args:
            sensitive_info_list: 敏感信息列表

        Returns:
            统计信息字典
        """
        stats = {
            "total": len(sensitive_info_list),
            "high": 0,
            "medium": 0,
            "low": 0,
            "by_category": {}
        }

        for info in sensitive_info_list:
            level = info.rule_level.lower()
            if level in stats:
                stats[level] += 1

        return stats

    def clear_cache(self):
        """清空正则表达式缓存"""
        self._get_compiled_pattern.cache_clear()
        logger.info("正则表达式缓存已清空")
