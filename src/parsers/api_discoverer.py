"""
API 自动发现模块

本模块实现从目标网站自动发现 API 接口的功能，支持以下发现方式：
1. 爬取网页中的 API 链接和端点
2. 常见 API 路径探测
3. JavaScript 文件中的 API 路径提取
4. 响应头中的 API 信息提取
5. sitemap.xml / robots.txt 解析
"""

import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from ..core.models import APIEndpoint, Parameter

logger = logging.getLogger(__name__)


class APIDiscoverer:
    """
    API 自动发现器
    
    从目标 URL 自动发现 API 接口，支持多种发现策略。
    
    Attributes:
        http_client: HTTP 客户端实例
        discovered_urls: 已发现的 URL 集合
        discovered_endpoints: 已发现的 APIEndpoint 列表
    """
    
    COMMON_API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/v1", "/v2", "/v3",
        "/rest", "/rest/api", "/graphql",
        "/swagger", "/swagger.json", "/swagger-ui", "/swagger-resources",
        "/api-docs", "/api-docs.json", "/docs", "/openapi.json", "/openapi.yaml",
        "/.well-known/openapi", "/spec", "/api/spec",
        "/health", "/status", "/info", "/version", "/ping",
        "/auth", "/auth/login", "/auth/register", "/auth/logout", "/auth/token",
        "/users", "/user", "/accounts", "/account",
        "/login", "/logout", "/register", "/signup", "/signin",
        "/admin", "/admin/login", "/admin/api",
        "/config", "/settings", "/preferences",
        "/search", "/query", "/filter",
        "/upload", "/file", "/files", "/download",
        "/orders", "/products", "/items", "/resources",
        "/posts", "/comments", "/messages", "/notifications",
        "/webhook", "/callbacks", "/events",
        "/sitemap.xml", "/robots.txt",
    ]
    
    JS_API_PATTERNS = [
        re.compile(r'''['"`](/(?:api|v[0-9]+|rest)/[^'"`\s]+)['"`]'''),
        re.compile(r'''['"`](https?://[^'"`\s]+/api/[^'"`\s]+)['"`]'''),
        re.compile(r'''['"`](/[^'"`\s]*(?:user|auth|login|admin|search|upload|file|order|product)[^'"`\s]*)['"`]'''),
        re.compile(r'''(?:fetch|axios|http\.get|http\.post|http\.put|http\.delete)\s*\(\s*['"`]([^'"`\s]+)['"`]'''),
        re.compile(r'''(?:url|endpoint|uri|path)\s*[:=]\s*['"`]([^'"`\s]+)['"`]'''),
        re.compile(r'''['"`](/[^'"`\s]*\{[^}]+\}[^'"`\s]*)['"`]'''),
    ]
    
    HTML_API_PATTERNS = [
        re.compile(r'''(?:action|href|src)\s*=\s*['"`]([^'"`\s]*(?:api|rest|v[0-9]+)[^'"`\s]*)['"`]''', re.IGNORECASE),
        re.compile(r'''['"`](https?://[^'"`\s]+/api/[^'"`\s]+)['"`]'''),
    ]
    
    HTTP_METHOD_PATTERNS = {
        "GET": re.compile(r'\bGET\b', re.IGNORECASE),
        "POST": re.compile(r'\bPOST\b', re.IGNORECASE),
        "PUT": re.compile(r'\bPUT\b', re.IGNORECASE),
        "DELETE": re.compile(r'\bDELETE\b', re.IGNORECASE),
        "PATCH": re.compile(r'\bPATCH\b', re.IGNORECASE),
    }
    
    def __init__(self, timeout: int = 15, verify_ssl: bool = True, max_depth: int = 2):
        """
        初始化 API 自动发现器
        
        Args:
            timeout: 请求超时时间（秒）
            verify_ssl: 是否验证 SSL 证书
            max_depth: 爬取最大深度
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_depth = max_depth
        self.discovered_urls: Set[str] = set()
        self.discovered_endpoints: List[APIEndpoint] = []
        self._visited_urls: Set[str] = set()
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/json,application/javascript,*/*",
        })
        self._base_url = ""
        self._progress_callback = None
        
        logger.info(f"APIDiscoverer initialized: timeout={timeout}s, max_depth={max_depth}")
    
    def set_progress_callback(self, callback):
        """设置进度回调"""
        self._progress_callback = callback
    
    def _notify_progress(self, message: str, progress: int = 0):
        """通知进度"""
        if self._progress_callback:
            try:
                self._progress_callback(message, progress)
            except Exception:
                pass
    
    def discover(self, target_url: str, strategies: List[str] = None) -> List[APIEndpoint]:
        """
        从目标 URL 自动发现 API 接口
        
        Args:
            target_url: 目标 URL
            strategies: 发现策略列表，默认全部启用
                - "crawl": 爬取网页链接
                - "probe": 常见路径探测
                - "js": JavaScript 文件分析
                - "sitemap": sitemap/robots 解析
                - "headers": 响应头分析
        
        Returns:
            发现的 APIEndpoint 列表
        """
        self._base_url = self._normalize_url(target_url)
        self.discovered_urls.clear()
        self.discovered_endpoints.clear()
        self._visited_urls.clear()
        
        if strategies is None:
            strategies = ["crawl", "probe", "js", "sitemap", "headers"]
        
        logger.info(f"Starting API discovery: {self._base_url}, strategies={strategies}")
        
        total_steps = len(strategies)
        
        for i, strategy in enumerate(strategies):
            progress = int((i / total_steps) * 100)
            self._notify_progress(f"正在执行 {strategy} 策略...", progress)
            
            try:
                if strategy == "crawl":
                    self._strategy_crawl()
                elif strategy == "probe":
                    self._strategy_probe()
                elif strategy == "js":
                    self._strategy_js()
                elif strategy == "sitemap":
                    self._strategy_sitemap()
                elif strategy == "headers":
                    self._strategy_headers()
            except Exception as e:
                logger.error(f"Strategy {strategy} failed: {e}")
        
        self._convert_urls_to_endpoints()
        
        self._notify_progress(f"发现完成: {len(self.discovered_endpoints)} 个 API", 100)
        logger.info(f"API discovery completed: {len(self.discovered_endpoints)} endpoints found")
        
        return self.discovered_endpoints
    
    def _normalize_url(self, url: str) -> str:
        """标准化 URL"""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _is_same_origin(self, url: str) -> bool:
        """检查 URL 是否同源"""
        try:
            parsed = urlparse(url)
            base_parsed = urlparse(self._base_url)
            return parsed.netloc == base_parsed.netloc
        except Exception:
            return False
    
    def _fetch(self, url: str) -> Optional[requests.Response]:
        """发送 HTTP 请求"""
        if url in self._visited_urls:
            return None
        self._visited_urls.add(url)
        
        try:
            response = self._session.get(url, timeout=self.timeout, allow_redirects=True)
            return response
        except requests.RequestException as e:
            logger.debug(f"Fetch failed: {url} - {e}")
            return None
    
    def _strategy_crawl(self):
        """策略1: 爬取网页中的 API 链接"""
        logger.info("Strategy: crawling web pages")
        
        response = self._fetch(self._base_url)
        if not response:
            return
        
        self._extract_urls_from_html(response.text, self._base_url)
        
        for link in list(self.discovered_urls)[:20]:
            if len(self._visited_urls) > 50:
                break
            sub_response = self._fetch(link)
            if sub_response:
                self._extract_urls_from_html(sub_response.text, link)
    
    def _extract_urls_from_html(self, html: str, base_url: str):
        """从 HTML 中提取 URL"""
        soup = BeautifulSoup(html, "lxml")
        
        for tag in soup.find_all(["a", "link", "script", "form", "iframe"]):
            attr = "href"
            if tag.name == "script":
                attr = "src"
            elif tag.name == "form":
                attr = "action"
            
            url = tag.get(attr, "")
            if url:
                full_url = urljoin(base_url, url)
                if self._is_same_origin(full_url) and full_url not in self.discovered_urls:
                    self.discovered_urls.add(full_url)
                    logger.debug(f"Found URL from HTML: {full_url}")
        
        for pattern in self.HTML_API_PATTERNS:
            for match in pattern.findall(html):
                full_url = urljoin(base_url, match)
                if self._is_same_origin(full_url):
                    self.discovered_urls.add(full_url)
    
    def _strategy_probe(self):
        """策略2: 常见 API 路径探测"""
        logger.info("Strategy: probing common API paths")
        
        for path in self.COMMON_API_PATHS:
            url = f"{self._base_url}{path}"
            try:
                response = self._session.get(url, timeout=self.timeout, allow_redirects=False)
                if response.status_code in (200, 201, 301, 302, 401, 403, 405):
                    self.discovered_urls.add(url)
                    logger.debug(f"Found API path: {url} (status={response.status_code})")
                    
                    if response.status_code == 200:
                        content_type = response.headers.get("Content-Type", "")
                        if "json" in content_type:
                            self._extract_urls_from_json(response.text, url)
            except requests.RequestException:
                pass
    
    def _strategy_js(self):
        """策略3: JavaScript 文件分析"""
        logger.info("Strategy: analyzing JavaScript files")
        
        response = self._fetch(self._base_url)
        if not response:
            return
        
        soup = BeautifulSoup(response.text, "lxml")
        js_urls = []
        
        for script in soup.find_all("script", src=True):
            js_url = urljoin(self._base_url, script["src"])
            if self._is_same_origin(js_url):
                js_urls.append(js_url)
        
        for js_url in js_urls[:30]:
            try:
                js_response = self._session.get(js_url, timeout=self.timeout)
                if js_response.status_code == 200:
                    self._extract_urls_from_js(js_response.text, js_url)
            except requests.RequestException:
                pass
    
    def _extract_urls_from_js(self, js_content: str, base_url: str):
        """从 JavaScript 内容中提取 API 路径"""
        for pattern in self.JS_API_PATTERNS:
            for match in pattern.findall(js_content):
                if match.startswith("/"):
                    full_url = f"{self._base_url}{match}"
                elif match.startswith("http"):
                    full_url = match
                else:
                    full_url = urljoin(base_url, match)
                
                if self._is_same_origin(full_url):
                    self.discovered_urls.add(full_url)
                    logger.debug(f"Found API path from JS: {full_url}")
    
    def _extract_urls_from_json(self, json_text: str, base_url: str):
        """从 JSON 响应中提取 URL"""
        url_pattern = re.compile(r'(https?://[^\s"\'<>]+|/[a-zA-Z0-9_/.-]+)')
        for match in url_pattern.findall(json_text):
            if match.startswith("/"):
                full_url = f"{self._base_url}{match}"
            else:
                full_url = match
            if self._is_same_origin(full_url):
                self.discovered_urls.add(full_url)
    
    def _strategy_sitemap(self):
        """策略4: sitemap.xml 和 robots.txt 解析"""
        logger.info("Strategy: parsing sitemap and robots")
        
        for path in ["/sitemap.xml", "/robots.txt"]:
            url = f"{self._base_url}{path}"
            try:
                response = self._session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    if path == "/sitemap.xml":
                        self._parse_sitemap(response.text)
                    else:
                        self._parse_robots(response.text)
            except requests.RequestException:
                pass
    
    def _parse_sitemap(self, xml_content: str):
        """解析 sitemap.xml"""
        soup = BeautifulSoup(xml_content, "lxml-xml")
        for loc in soup.find_all("loc"):
            url = loc.text.strip()
            if self._is_same_origin(url):
                self.discovered_urls.add(url)
                logger.debug(f"Found URL from sitemap: {url}")
    
    def _parse_robots(self, robots_content: str):
        """解析 robots.txt"""
        for line in robots_content.splitlines():
            line = line.strip()
            if line.startswith(("Allow:", "Disallow:", "Sitemap:")):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    path = parts[1].strip()
                    if path and path != "/":
                        if path.startswith("http"):
                            if self._is_same_origin(path):
                                self.discovered_urls.add(path)
                        else:
                            full_url = f"{self._base_url}{path}"
                            self.discovered_urls.add(full_url)
                            logger.debug(f"Found URL from robots.txt: {full_url}")
    
    def _strategy_headers(self):
        """策略5: 响应头分析"""
        logger.info("Strategy: analyzing response headers")
        
        try:
            response = self._session.get(self._base_url, timeout=self.timeout)
            headers = response.headers
            
            for header_name in ["Link", "X-API-Version", "Server", "X-Powered-By"]:
                value = headers.get(header_name, "")
                if value:
                    urls = re.findall(r'(https?://[^\s<>"]+|/[a-zA-Z0-9_/.-]+)', value)
                    for url in urls:
                        if url.startswith("/"):
                            full_url = f"{self._base_url}{url}"
                        else:
                            full_url = url
                        if self._is_same_origin(full_url):
                            self.discovered_urls.add(full_url)
            
            link_header = headers.get("Link", "")
            for match in re.findall(r'<([^>]+)>', link_header):
                full_url = urljoin(self._base_url, match)
                if self._is_same_origin(full_url):
                    self.discovered_urls.add(full_url)
                    
        except requests.RequestException:
            pass
    
    def _convert_urls_to_endpoints(self):
        """将发现的 URL 转换为 APIEndpoint 对象"""
        seen_paths: Set[str] = set()
        
        for url in sorted(self.discovered_urls):
            parsed = urlparse(url)
            path = parsed.path
            
            if path in seen_paths:
                continue
            seen_paths.add(path)
            
            query_params = parse_qs(parsed.query)
            parameters = []
            for name, values in query_params.items():
                parameters.append(Parameter(
                    name=name,
                    param_type="query",
                    data_type="string",
                    required=False,
                    example=values[0] if values else None,
                ))
            
            path_segments = [s for s in path.split("/") if s]
            is_likely_api = any(
                keyword in path.lower()
                for keyword in ["api", "v1", "v2", "v3", "rest", "graphql", "auth", "user", "admin", "login", "search", "upload", "order", "product"]
            )
            
            if not is_likely_api and not parameters:
                if not any(ext in path.lower() for ext in [".json", ".xml", ".yaml"]):
                    if not any(seg.isdigit() or ("{" in seg) for seg in path_segments):
                        continue
            
            methods = self._guess_methods(path)
            
            for method in methods:
                endpoint = APIEndpoint(
                    url=url,
                    method=method,
                    path=path,
                    summary=f"Auto-discovered: {method} {path}",
                    description=f"Discovered from {self._base_url}",
                    parameters=parameters,
                    tags=["auto-discovered"],
                )
                self.discovered_endpoints.append(endpoint)
        
        logger.info(f"Converted {len(self.discovered_endpoints)} endpoints from {len(self.discovered_urls)} URLs")
    
    def _guess_methods(self, path: str) -> List[str]:
        """根据路径猜测可能的 HTTP 方法"""
        methods = ["GET"]
        path_lower = path.lower()
        
        if any(kw in path_lower for kw in ["create", "add", "register", "signup", "login", "upload", "post"]):
            methods.append("POST")
        if any(kw in path_lower for kw in ["update", "edit", "modify", "put", "patch", "settings", "config"]):
            methods.extend(["PUT", "PATCH"])
        if any(kw in path_lower for kw in ["delete", "remove", "destroy"]):
            methods.append("DELETE")
        
        if len(methods) == 1 and path.count("/") > 2:
            segments = [s for s in path.split("/") if s]
            last_segment = segments[-1] if segments else ""
            if last_segment and (last_segment.isdigit() or last_segment.startswith("{")):
                methods = ["GET", "PUT", "DELETE"]
        
        return methods
    
    def close(self):
        """关闭发现器"""
        self._session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
