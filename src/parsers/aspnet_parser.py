"""
ASP.NET Web API Help Page 解析器

本模块提供解析 ASP.NET Web API Help Page 的功能，从 HTML 页面提取 API 接口信息。
"""

import logging
import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from ..core.models import APIEndpoint, Parameter


class AspNetParser:
    """
    ASP.NET Web API Help Page 解析器
    
    用于解析 ASP.NET Web API 自动生成的 Help Page，提取 API 接口信息。
    
    Attributes:
        timeout: 请求超时时间（秒）
        session: requests Session 对象
        logger: 日志记录器
    """
    
    def __init__(self, timeout: int = 30):
        """
        初始化解析器
        
        Args:
            timeout: 请求超时时间（秒）
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.logger = logging.getLogger(__name__)
    
    def parse_from_url(self, url: str) -> List[APIEndpoint]:
        """
        从 URL 解析 ASP.NET Help Page
        
        Args:
            url: Help Page 的 URL（通常是 /Help 页面）
        
        Returns:
            API 接口列表
        
        Raises:
            ValueError: URL 格式无效
            requests.RequestException: 网络请求失败
        """
        self.logger.info(f"开始解析 ASP.NET Help Page: {url}")
        
        if not self._is_valid_url(url):
            raise ValueError(f"无效的 URL: {url}")
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            response.encoding = response.apparent_encoding
            
            self.logger.debug(f"成功获取页面内容，长度: {len(response.text)}")
            
            endpoints = self._extract_endpoints(response.text, url)
            
            self.logger.info(f"成功解析 {len(endpoints)} 个 API 接口")
            return endpoints
            
        except requests.RequestException as e:
            self.logger.error(f"网络请求失败: {e}")
            raise
        except Exception as e:
            self.logger.error(f"解析页面失败: {e}")
            raise
    
    def _extract_endpoints(self, html: str, base_url: str) -> List[APIEndpoint]:
        """
        从 HTML 中提取接口列表
        
        Args:
            html: HTML 内容
            base_url: 基础 URL，用于拼接相对路径
        
        Returns:
            API 接口列表
        """
        endpoints = []
        
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            api_table = self._find_api_table(soup)
            
            if not api_table:
                self.logger.warning("未找到 API 列表表格，尝试其他解析方式")
                return self._extract_endpoints_alternative(soup, base_url)
            
            rows = api_table.find_all('tr')
            
            for row in rows:
                endpoint = self._parse_table_row(row, base_url)
                if endpoint:
                    endpoints.append(endpoint)
            
            return endpoints
            
        except Exception as e:
            self.logger.error(f"提取接口列表失败: {e}")
            return []
    
    def _find_api_table(self, soup: BeautifulSoup) -> Optional[BeautifulSoup]:
        """
        查找 API 列表表格
        
        ASP.NET Help Page 通常使用以下结构：
        - <table class="..."> 包含 API 列表
        - 或 <div class="api-list"> 结构
        
        Args:
            soup: BeautifulSoup 对象
        
        Returns:
            表格元素或 None
        """
        table_selectors = [
            'table.help-page-table',
            'table.table',
            'table',
            '.api-list',
            '#api-list'
        ]
        
        for selector in table_selectors:
            table = soup.select_one(selector)
            if table:
                self.logger.debug(f"找到 API 表格: {selector}")
                return table
        
        return None
    
    def _parse_table_row(self, row: BeautifulSoup, base_url: str) -> Optional[APIEndpoint]:
        """
        解析表格行，提取接口信息
        
        Args:
            row: 表格行元素
            base_url: 基础 URL
        
        Returns:
            APIEndpoint 对象或 None
        """
        try:
            cells = row.find_all('td')
            
            if len(cells) < 2:
                return None
            
            method_cell = cells[0]
            api_link = cells[1].find('a')
            
            if not api_link:
                return None
            
            method = method_cell.get_text(strip=True).upper()
            api_path = api_link.get_text(strip=True)
            detail_url = api_link.get('href', '')
            
            if detail_url and not detail_url.startswith('http'):
                detail_url = urljoin(base_url, detail_url)
            
            description = cells[2].get_text(strip=True) if len(cells) > 2 else ""
            
            endpoint = APIEndpoint(
                url=detail_url,
                method=method,
                path=api_path,
                description=description
            )
            
            if detail_url:
                self._parse_endpoint_detail(detail_url, endpoint)
            
            return endpoint
            
        except Exception as e:
            self.logger.debug(f"解析表格行失败: {e}")
            return None
    
    def _parse_endpoint_detail(self, url: str, endpoint: APIEndpoint) -> None:
        """
        解析接口详情页面，补充参数和示例信息
        
        Args:
            url: 详情页面 URL
            endpoint: APIEndpoint 对象（会被修改）
        """
        try:
            self.logger.debug(f"解析接口详情: {url}")
            
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            response.encoding = response.apparent_encoding
            
            soup = BeautifulSoup(response.text, 'lxml')
            
            parameters = self._extract_parameters(soup)
            endpoint.parameters = parameters
            
            sample_request = self._extract_sample_request(soup)
            if sample_request:
                endpoint.headers['_sample_request'] = sample_request
            
            self.logger.debug(f"成功解析接口详情，参数数量: {len(parameters)}")
            
        except requests.RequestException as e:
            self.logger.warning(f"获取接口详情失败: {e}")
        except Exception as e:
            self.logger.warning(f"解析接口详情失败: {e}")
    
    def _extract_parameters(self, soup: BeautifulSoup) -> List[Parameter]:
        """
        从详情页面提取参数列表
        
        ASP.NET Help Page 通常包含参数表格，列包括：
        - Name: 参数名
        - Description: 描述
        - Type: 数据类型
        - Additional info: 额外信息（如是否必需）
        
        Args:
            soup: BeautifulSoup 对象
        
        Returns:
            参数列表
        """
        parameters = []
        
        try:
            param_table = self._find_parameter_table(soup)
            
            if not param_table:
                return parameters
            
            rows = param_table.find_all('tr')
            
            for row in rows:
                param = self._parse_parameter_row(row)
                if param:
                    parameters.append(param)
            
        except Exception as e:
            self.logger.debug(f"提取参数失败: {e}")
        
        return parameters
    
    def _find_parameter_table(self, soup: BeautifulSoup) -> Optional[BeautifulSoup]:
        """
        查找参数表格
        
        Args:
            soup: BeautifulSoup 对象
        
        Returns:
            参数表格元素或 None
        """
        param_selectors = [
            'h2:contains("Parameter") + table',
            'h3:contains("Parameter") + table',
            '.parameter-table',
            'table.parameters'
        ]
        
        for selector in param_selectors:
            try:
                table = soup.select_one(selector)
                if table:
                    return table
            except Exception:
                continue
        
        headers = soup.find_all(['h2', 'h3'])
        for header in headers:
            if 'parameter' in header.get_text().lower():
                table = header.find_next('table')
                if table:
                    return table
        
        return None
    
    def _parse_parameter_row(self, row: BeautifulSoup) -> Optional[Parameter]:
        """
        解析参数表格行
        
        Args:
            row: 表格行元素
        
        Returns:
            Parameter 对象或 None
        """
        try:
            cells = row.find_all('td')
            
            if len(cells) < 2:
                return None
            
            name = cells[0].get_text(strip=True)
            
            if not name or name.lower() == 'name':
                return None
            
            description = cells[1].get_text(strip=True) if len(cells) > 1 else ""
            data_type = cells[2].get_text(strip=True) if len(cells) > 2 else "string"
            additional_info = cells[3].get_text(strip=True) if len(cells) > 3 else ""
            
            required = 'required' in additional_info.lower() or '必需' in additional_info
            
            param_type = self._determine_param_type(name, description)
            
            return Parameter(
                name=name,
                param_type=param_type,
                data_type=data_type,
                required=required,
                description=description
            )
            
        except Exception as e:
            self.logger.debug(f"解析参数行失败: {e}")
            return None
    
    def _determine_param_type(self, name: str, description: str) -> str:
        """
        判断参数类型
        
        Args:
            name: 参数名
            description: 参数描述
        
        Returns:
            参数类型
        """
        desc_lower = description.lower()
        name_lower = name.lower()
        
        if 'header' in desc_lower or '请求头' in description or name_lower.startswith('x-') or name_lower in ['authorization', 'content-type', 'accept']:
            return 'header'
        
        if 'path' in desc_lower or 'uri' in desc_lower or 'route' in desc_lower or '路径' in description:
            return 'path'
        
        if 'body' in desc_lower or 'request body' in desc_lower or '请求体' in description:
            return 'body'
        
        return 'query'
    
    def _extract_sample_request(self, soup: BeautifulSoup) -> str:
        """
        提取示例请求
        
        ASP.NET Help Page 通常包含请求示例，格式可能是：
        - JSON 示例
        - XML 示例
        
        Args:
            soup: BeautifulSoup 对象
        
        Returns:
            示例请求字符串
        """
        try:
            sample_selectors = [
                '.sample-request',
                '.request-sample',
                'pre.sample',
                'pre:contains("{")',
                'pre:contains("<")'
            ]
            
            for selector in sample_selectors:
                try:
                    sample_elem = soup.select_one(selector)
                    if sample_elem:
                        sample_text = sample_elem.get_text(strip=True)
                        if sample_text and (sample_text.startswith('{') or sample_text.startswith('<')):
                            return sample_text
                except Exception:
                    continue
            
            headers = soup.find_all(['h2', 'h3', 'h4'])
            for header in headers:
                header_text = header.get_text().lower()
                if 'sample' in header_text or 'request' in header_text or '示例' in header_text:
                    pre = header.find_next('pre')
                    if pre:
                        return pre.get_text(strip=True)
            
            return ""
            
        except Exception as e:
            self.logger.debug(f"提取示例请求失败: {e}")
            return ""
    
    def _extract_parameters_from_sample(self, sample: str) -> List[Parameter]:
        """
        从示例请求中提取参数
        
        支持 JSON 和 XML 格式的示例
        
        Args:
            sample: 示例请求字符串
        
        Returns:
            参数列表
        """
        parameters = []
        
        if not sample:
            return parameters
        
        try:
            if sample.strip().startswith('{'):
                parameters = self._extract_json_parameters(sample)
            elif sample.strip().startswith('<'):
                parameters = self._extract_xml_parameters(sample)
            
        except Exception as e:
            self.logger.debug(f"从示例提取参数失败: {e}")
        
        return parameters
    
    def _extract_json_parameters(self, json_str: str) -> List[Parameter]:
        """
        从 JSON 示例中提取参数
        
        Args:
            json_str: JSON 字符串
        
        Returns:
            参数列表
        """
        parameters = []
        
        try:
            import json
            data = json.loads(json_str)
            
            def extract_from_dict(d: dict, prefix: str = ""):
                for key, value in d.items():
                    full_name = f"{prefix}.{key}" if prefix else key
                    
                    if isinstance(value, dict):
                        extract_from_dict(value, full_name)
                    else:
                        data_type = type(value).__name__
                        parameters.append(Parameter(
                            name=full_name,
                            param_type='body',
                            data_type=data_type,
                            example=value
                        ))
            
            if isinstance(data, dict):
                extract_from_dict(data)
            
        except json.JSONDecodeError as e:
            self.logger.debug(f"JSON 解析失败: {e}")
        except Exception as e:
            self.logger.debug(f"提取 JSON 参数失败: {e}")
        
        return parameters
    
    def _extract_xml_parameters(self, xml_str: str) -> List[Parameter]:
        """
        从 XML 示例中提取参数
        
        Args:
            xml_str: XML 字符串
        
        Returns:
            参数列表
        """
        parameters = []
        
        try:
            xml_soup = BeautifulSoup(xml_str, 'lxml-xml')
            
            for element in xml_soup.find_all():
                if element.name and not element.name.startswith('?'):
                    text = element.get_text(strip=True)
                    if text and not element.find_all():
                        parameters.append(Parameter(
                            name=element.name,
                            param_type='body',
                            data_type='string',
                            example=text
                        ))
            
        except Exception as e:
            self.logger.debug(f"提取 XML 参数失败: {e}")
        
        return parameters
    
    def _extract_endpoints_alternative(self, soup: BeautifulSoup, base_url: str) -> List[APIEndpoint]:
        """
        使用替代方法提取接口列表
        
        当标准表格结构不存在时，尝试其他常见的结构
        
        Args:
            soup: BeautifulSoup 对象
            base_url: 基础 URL
        
        Returns:
            API 接口列表
        """
        endpoints = []
        
        try:
            api_links = soup.find_all('a', href=True)
            
            for link in api_links:
                href = link.get('href', '')
                text = link.get_text(strip=True)
                
                if '/Help/Api/' in href or '/api/' in href.lower():
                    method_match = re.match(r'^(GET|POST|PUT|DELETE|PATCH)\s+', text)
                    
                    if method_match:
                        method = method_match.group(1)
                        path = text[method_match.end():].strip()
                    else:
                        method = 'GET'
                        path = text
                    
                    detail_url = urljoin(base_url, href)
                    
                    endpoint = APIEndpoint(
                        url=detail_url,
                        method=method,
                        path=path
                    )
                    
                    self._parse_endpoint_detail(detail_url, endpoint)
                    endpoints.append(endpoint)
            
            self.logger.info(f"替代方法提取到 {len(endpoints)} 个接口")
            
        except Exception as e:
            self.logger.error(f"替代提取方法失败: {e}")
        
        return endpoints
    
    def _is_valid_url(self, url: str) -> bool:
        """
        验证 URL 格式是否有效
        
        Args:
            url: URL 字符串
        
        Returns:
            是否有效
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def close(self):
        """关闭 Session，释放资源"""
        self.session.close()
        self.logger.debug("Session 已关闭")
    
    def __enter__(self):
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.close()
