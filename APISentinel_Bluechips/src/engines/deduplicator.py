"""
结果去重引擎模块

本模块实现测试结果去重功能，支持指纹生成、状态码过滤、相似度去重等特性。
"""

import hashlib
import json
import logging
from difflib import SequenceMatcher
from pathlib import Path
from typing import Callable, Dict, List, Optional

from ..core.models import TestResult


logger = logging.getLogger(__name__)


class Deduplicator:
    """
    结果去重引擎
    
    提供测试结果去重功能，支持指纹生成、状态码过滤、相似度去重和持久化缓存。
    
    Attributes:
        fingerprint_generator: 自定义指纹生成函数
        similarity_threshold: 相似度阈值（0.0-1.0）
        enable_similarity: 是否启用相似度去重
    """
    
    def __init__(
        self,
        similarity_threshold: float = 0.85,
        enable_similarity: bool = False,
        fingerprint_generator: Optional[Callable[[int, int], str]] = None
    ):
        """
        初始化去重引擎
        
        Args:
            similarity_threshold: 相似度阈值，默认 0.85
            enable_similarity: 是否启用相似度去重，默认 False
            fingerprint_generator: 自定义指纹生成函数，签名为 (status_code, response_length) -> str
        """
        self._fingerprints: Dict[str, TestResult] = {}
        self._filter_status_codes: List[int] = []
        self._statistics = {
            "total": 0,
            "unique": 0,
            "duplicate": 0,
            "filtered": 0
        }
        self._similarity_threshold = similarity_threshold
        self._enable_similarity = enable_similarity
        self._fingerprint_generator = fingerprint_generator
        self._results_cache: List[TestResult] = []
        
        logger.info(
            f"去重引擎初始化完成 - 相似度阈值: {similarity_threshold}, "
            f"启用相似度去重: {enable_similarity}"
        )
    
    def generate_fingerprint(self, status_code: int, response_length: int) -> str:
        """
        生成响应指纹
        
        指纹格式：{status_code}_{response_length}
        
        Args:
            status_code: HTTP 状态码
            response_length: 响应长度（字节）
            
        Returns:
            指纹字符串
            
        Example:
            >>> deduplicator = Deduplicator()
            >>> fingerprint = deduplicator.generate_fingerprint(200, 1234)
            >>> print(fingerprint)
            '200_1234'
        """
        if self._fingerprint_generator:
            return self._fingerprint_generator(status_code, response_length)
        
        return f"{status_code}_{response_length}"
    
    def set_filter_status_codes(self, codes: List[int]) -> None:
        """
        设置要过滤的状态码列表
        
        Args:
            codes: 状态码列表
            
        Example:
            >>> deduplicator = Deduplicator()
            >>> deduplicator.set_filter_status_codes([404, 500])
        """
        self._filter_status_codes = codes
        logger.info(f"已设置过滤状态码: {codes}")
    
    def is_filtered(self, status_code: int) -> bool:
        """
        检查状态码是否被过滤
        
        Args:
            status_code: HTTP 状态码
            
        Returns:
            如果状态码在过滤列表中返回 True，否则返回 False
        """
        return status_code in self._filter_status_codes
    
    def is_duplicate(self, result: TestResult) -> bool:
        """
        检查结果是否重复
        
        基于指纹和相似度判断结果是否重复。
        
        Args:
            result: 测试结果对象
            
        Returns:
            如果结果重复返回 True，否则返回 False
        """
        if self.is_filtered(result.response_status):
            return False
        
        fingerprint = self.generate_fingerprint(result.response_status, result.response_length)
        
        if fingerprint in self._fingerprints:
            if self._enable_similarity:
                cached_result = self._fingerprints[fingerprint]
                similarity = self._calculate_similarity(
                    result.response_body,
                    cached_result.response_body
                )
                return similarity >= self._similarity_threshold
            return True
        
        return False
    
    def add_result(self, result: TestResult) -> bool:
        """
        添加结果到缓存
        
        Args:
            result: 测试结果对象
            
        Returns:
            如果结果被添加（非重复且未过滤）返回 True，否则返回 False
        """
        self._statistics["total"] += 1
        
        if self.is_filtered(result.response_status):
            self._statistics["filtered"] += 1
            logger.debug(f"结果被过滤: 状态码 {result.response_status}")
            return False
        
        fingerprint = self.generate_fingerprint(result.response_status, result.response_length)
        
        if fingerprint in self._fingerprints:
            if self._enable_similarity:
                cached_result = self._fingerprints[fingerprint]
                similarity = self._calculate_similarity(
                    result.response_body,
                    cached_result.response_body
                )
                if similarity >= self._similarity_threshold:
                    self._statistics["duplicate"] += 1
                    logger.debug(
                        f"检测到重复结果: 指纹 {fingerprint}, 相似度 {similarity:.2f}"
                    )
                    return False
            else:
                self._statistics["duplicate"] += 1
                logger.debug(f"检测到重复结果: 指纹 {fingerprint}")
                return False
        
        self._fingerprints[fingerprint] = result
        self._results_cache.append(result)
        self._statistics["unique"] += 1
        logger.debug(f"添加唯一结果: 指纹 {fingerprint}")
        
        return True
    
    def get_unique_results(self) -> List[TestResult]:
        """
        获取去重后的结果列表
        
        Returns:
            去重后的 TestResult 列表
        """
        return list(self._results_cache)
    
    def clear_cache(self) -> None:
        """
        清空缓存和统计信息
        """
        self._fingerprints.clear()
        self._results_cache.clear()
        self._statistics = {
            "total": 0,
            "unique": 0,
            "duplicate": 0,
            "filtered": 0
        }
        logger.info("缓存已清空")
    
    def deduplicate(self, results: List[TestResult]) -> List[TestResult]:
        """
        对结果列表进行去重
        
        Args:
            results: 测试结果列表
            
        Returns:
            去重后的结果列表
            
        Example:
            >>> deduplicator = Deduplicator()
            >>> unique_results = deduplicator.deduplicate(results)
        """
        logger.info(f"开始去重处理，共 {len(results)} 个结果")
        
        for result in results:
            self.add_result(result)
        
        unique_results = self.get_unique_results()
        stats = self.get_statistics()
        
        logger.info(
            f"去重完成 - 总数: {stats['total']}, "
            f"唯一: {stats['unique']}, "
            f"重复: {stats['duplicate']}, "
            f"过滤: {stats['filtered']}"
        )
        
        return unique_results
    
    def get_statistics(self) -> Dict[str, int]:
        """
        获取去重统计信息
        
        Returns:
            包含统计信息的字典:
            - total: 总数
            - unique: 唯一数
            - duplicate: 重复数
            - filtered: 过滤数
        """
        return dict(self._statistics)
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """
        计算两个文本的相似度
        
        使用 SequenceMatcher 计算相似度。
        
        Args:
            text1: 第一个文本
            text2: 第二个文本
            
        Returns:
            相似度值（0.0-1.0）
        """
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0
        
        return SequenceMatcher(None, text1, text2).ratio()
    
    def set_similarity_threshold(self, threshold: float) -> None:
        """
        设置相似度阈值
        
        Args:
            threshold: 相似度阈值（0.0-1.0）
            
        Raises:
            ValueError: 如果阈值不在有效范围内
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"相似度阈值必须在 0.0 到 1.0 之间，当前值: {threshold}")
        
        self._similarity_threshold = threshold
        logger.info(f"相似度阈值已更新为: {threshold}")
    
    def enable_similarity_dedup(self, enable: bool = True) -> None:
        """
        启用或禁用相似度去重
        
        Args:
            enable: 是否启用，默认 True
        """
        self._enable_similarity = enable
        logger.info(f"相似度去重已{'启用' if enable else '禁用'}")
    
    def set_custom_fingerprint_generator(
        self,
        generator: Optional[Callable[[int, int], str]]
    ) -> None:
        """
        设置自定义指纹生成函数
        
        Args:
            generator: 指纹生成函数，签名为 (status_code, response_length) -> str
                      传入 None 恢复默认生成器
                      
        Example:
            >>> def custom_generator(status_code: int, response_length: int) -> str:
            ...     return f"custom_{status_code}_{response_length}"
            >>> deduplicator.set_custom_fingerprint_generator(custom_generator)
        """
        self._fingerprint_generator = generator
        logger.info(f"自定义指纹生成器已{'设置' if generator else '清除'}")
    
    def save_cache(self, file_path: str) -> bool:
        """
        保存缓存到文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            保存成功返回 True，失败返回 False
        """
        try:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            cache_data = {
                "fingerprints": {
                    fp: {
                        "request_id": result.request_id,
                        "endpoint_url": result.endpoint.url,
                        "endpoint_method": result.endpoint.method,
                        "endpoint_path": result.endpoint.path,
                        "response_status": result.response_status,
                        "response_length": result.response_length,
                        "response_time": result.response_time,
                        "error": result.error
                    }
                    for fp, result in self._fingerprints.items()
                },
                "statistics": self._statistics,
                "filter_status_codes": self._filter_status_codes,
                "similarity_threshold": self._similarity_threshold,
                "enable_similarity": self._enable_similarity
            }
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"缓存已保存到: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"保存缓存失败: {e}")
            return False
    
    def load_cache(self, file_path: str) -> bool:
        """
        从文件加载缓存
        
        注意：加载的缓存只包含元数据，不包含完整的 TestResult 对象。
        加载后主要用于检查重复，不能通过 get_unique_results() 获取完整结果。
        
        Args:
            file_path: 文件路径
            
        Returns:
            加载成功返回 True，失败返回 False
        """
        try:
            path = Path(file_path)
            
            if not path.exists():
                logger.warning(f"缓存文件不存在: {file_path}")
                return False
            
            with open(path, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            self._fingerprints = {}
            self._results_cache = []
            
            self._statistics = cache_data.get("statistics", {
                "total": 0,
                "unique": 0,
                "duplicate": 0,
                "filtered": 0
            })
            self._filter_status_codes = cache_data.get("filter_status_codes", [])
            self._similarity_threshold = cache_data.get("similarity_threshold", 0.85)
            self._enable_similarity = cache_data.get("enable_similarity", False)
            
            for fp in cache_data.get("fingerprints", {}):
                self._fingerprints[fp] = None
            
            logger.info(f"缓存已从 {file_path} 加载，共 {len(self._fingerprints)} 个指纹")
            return True
            
        except Exception as e:
            logger.error(f"加载缓存失败: {e}")
            return False
    
    def get_fingerprint_count(self) -> int:
        """
        获取当前缓存的指纹数量
        
        Returns:
            指纹数量
        """
        return len(self._fingerprints)
    
    def has_fingerprint(self, fingerprint: str) -> bool:
        """
        检查指纹是否存在
        
        Args:
            fingerprint: 指纹字符串
            
        Returns:
            如果指纹存在返回 True，否则返回 False
        """
        return fingerprint in self._fingerprints
    
    def __len__(self) -> int:
        """返回缓存中的结果数量"""
        return len(self._results_cache)
    
    def __repr__(self) -> str:
        """返回对象的字符串表示"""
        return (
            f"Deduplicator(unique={self._statistics['unique']}, "
            f"duplicate={self._statistics['duplicate']}, "
            f"filtered={self._statistics['filtered']})"
        )
