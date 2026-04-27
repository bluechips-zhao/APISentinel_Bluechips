"""
APISentinel_Bluechips - API 安全扫描器主窗口
Author: bluechips
Version: 1.0.0

专为渗透测试人员打造的 API 接口自动化安全检测工具
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QTreeWidget, QTreeWidgetItem, QProgressBar, QStatusBar, QToolBar,
    QSplitter, QMenu, QDialog, QTextEdit, QCheckBox, QListWidget,
    QListWidgetItem, QInputDialog, QFileDialog, QMessageBox, QFrame,
    QGraphicsDropShadowEffect, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve, QSize, QTimer, QSequentialAnimationGroup, QParallelAnimationGroup
from PyQt6.QtGui import QIcon, QColor, QFont, QAction, QPalette, QLinearGradient, QPainter, QPen, QBrush

from src.parsers import SwaggerParser, AspNetParser
from src.engines import TestExecutor, Deduplicator, SafeMode
from src.core.models import APIEndpoint
from src.core.http_client import HttpClient


APP_NAME = "APISentinel_Bluechips"
APP_AUTHOR = "bluechips"
APP_VERSION = "1.0.1"


class ModernButton(QPushButton):
    """现代化按钮 - bluechips 设计，带丝滑动画"""
    
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._scale = 1.0
        self._shadow_offset = 4
        self._animation = None
    
    def enterEvent(self, event):
        self._animate_scale(1.03)
        self._animate_shadow(8)
        super().enterEvent(event)
    
    def leaveEvent(self, event):
        self._animate_scale(1.0)
        self._animate_shadow(4)
        super().leaveEvent(event)
    
    def _animate_scale(self, target):
        animation = QPropertyAnimation(self, b"geometry")
        animation.setDuration(150)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        geo = self.geometry()
        center = geo.center()
        new_w = int(geo.width() * target)
        new_h = int(geo.height() * target)
        new_geo = geo.__class__(0, 0, new_w, new_h)
        new_geo.moveCenter(center)
        animation.setStartValue(geo)
        animation.setEndValue(new_geo)
        animation.start()
        self._animation = animation
    
    def _animate_shadow(self, offset):
        effect = self.graphicsEffect()
        if effect and isinstance(effect, QGraphicsDropShadowEffect):
            animation = QPropertyAnimation(effect, b"offset")
            animation.setDuration(150)
            animation.setEasingCurve(QEasingCurve.Type.OutCubic)
            animation.setEndValue(QPointF(0, offset))
            animation.start()


class ModernGroupBox(QGroupBox):
    """现代化分组框 - 无边框阴影效果，带丝滑动画"""
    
    def __init__(self, title="", parent=None):
        super().__init__(title, parent)
        self._setup_shadow()
    
    def _setup_shadow(self):
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 40))
        shadow.setOffset(0, 4)
        self.setGraphicsEffect(shadow)
    
    def enterEvent(self, event):
        effect = self.graphicsEffect()
        if effect and isinstance(effect, QGraphicsDropShadowEffect):
            anim = QPropertyAnimation(effect, b"blurRadius")
            anim.setDuration(200)
            anim.setEasingCurve(QEasingCurve.Type.OutCubic)
            anim.setEndValue(30)
            anim.start()
            self._anim = anim
        super().enterEvent(event)
    
    def leaveEvent(self, event):
        effect = self.graphicsEffect()
        if effect and isinstance(effect, QGraphicsDropShadowEffect):
            anim = QPropertyAnimation(effect, b"blurRadius")
            anim.setDuration(200)
            anim.setEasingCurve(QEasingCurve.Type.OutCubic)
            anim.setEndValue(20)
            anim.start()
            self._anim = anim
        super().leaveEvent(event)


class TestWorker(QThread):
    """测试执行工作线程"""
    progress = pyqtSignal(int, int)
    result_ready = pyqtSignal(object)
    finished_all = pyqtSignal(list)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, executor, endpoints, max_workers=5):
        super().__init__()
        self.executor = executor
        self.endpoints = endpoints
        self.max_workers = max_workers
        self._is_stopped = False
    
    def run(self):
        results = []
        total = len(self.endpoints)
        
        for i, endpoint in enumerate(self.endpoints):
            if self._is_stopped:
                break
            try:
                result = self.executor.execute_endpoint(endpoint)
                results.append(result)
                self.result_ready.emit(result)
            except Exception as e:
                self.error_occurred.emit(f"{endpoint.method} {endpoint.path}: {str(e)}")
            self.progress.emit(i + 1, total)
        
        self.finished_all.emit(results)
    
    def stop(self):
        self._is_stopped = True


class _DiscoverWorker(QThread):
    """API 自动发现工作线程"""
    progress_ready = pyqtSignal(str, int)
    finished_ready = pyqtSignal(list)
    
    def __init__(self, target_url, strategies=None, timeout=15):
        super().__init__()
        self.target_url = target_url
        self.strategies = strategies
        self.timeout = timeout
    
    def run(self):
        try:
            from src.parsers import APIDiscoverer
            with APIDiscoverer(timeout=self.timeout) as discoverer:
                discoverer.set_progress_callback(
                    lambda msg, pct: self.progress_ready.emit(msg, pct)
                )
                endpoints = discoverer.discover(self.target_url, self.strategies)
                self.finished_ready.emit(endpoints)
        except Exception as e:
            self.progress_ready.emit(f"❌ 发现失败: {e}", 0)
            self.finished_ready.emit([])


class _FuzzWorker(QThread):
    """Fuzzer 工作线程"""
    progress = pyqtSignal(int, int)
    result_ready = pyqtSignal(object)
    finished_all = pyqtSignal(list)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, fuzzer, endpoints, http_client, category=None):
        super().__init__()
        self.fuzzer = fuzzer
        self.endpoints = endpoints
        self.http_client = http_client
        self.category = category
        self._is_stopped = False
    
    def run(self):
        all_results = []
        total = len(self.endpoints)
        
        for i, endpoint in enumerate(self.endpoints):
            if self._is_stopped:
                break
            try:
                results = self.fuzzer.test_endpoint(
                    endpoint, self.http_client,
                    category=self.category
                )
                for result in results:
                    all_results.append(result)
                    self.result_ready.emit(result)
            except Exception as e:
                self.error_occurred.emit(f"Fuzz {endpoint.method} {endpoint.path}: {str(e)}")
            self.progress.emit(i + 1, total)
        
        self.finished_all.emit(all_results)
    
    def stop(self):
        self._is_stopped = True


class MainWindow(QMainWindow):
    """APISentinel_Bluechips 主窗口 - by bluechips"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setGeometry(100, 100, 1400, 900)
        
        self._setup_window_icon()
        self._apply_modern_style()
        
        self._init_ui()
        self._init_signals()
        self._play_entrance_animation()
        
        self.http_client = HttpClient()
        self.test_executor = TestExecutor(
            enable_sensitive_detection=True,
            enable_jwt_detection=True,
            enable_idor_detection=False,
            enable_auth_bypass_detection=False,
            enable_upload_detection=False
        )
        self.safe_mode = SafeMode()
        self.deduplicator = Deduplicator()
        
        self.endpoints = []
        self.test_results = []
    
    def _setup_window_icon(self):
        """设置窗口图标"""
        from PyQt6.QtGui import QPixmap, QPainter, QFont, QFontMetrics
        from PyQt6.QtCore import QRect
        
        pixmap = QPixmap(256, 256)
        pixmap.fill(Qt.GlobalColor.transparent)
        
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        
        gradient = QLinearGradient(0, 0, 256, 256)
        gradient.setColorAt(0, QColor(14, 165, 233))
        gradient.setColorAt(0.5, QColor(6, 182, 212))
        gradient.setColorAt(1, QColor(20, 184, 166))
        
        painter.setBrush(gradient)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(10, 10, 236, 236, 40, 40)
        
        painter.setPen(QColor(255, 255, 255))
        font = QFont("Arial", 100, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(QRect(0, 0, 256, 256), Qt.AlignmentFlag.AlignCenter, "🛡️")
        
        painter.end()
        
        self.setWindowIcon(QIcon(pixmap))
    
    def _apply_modern_style(self):
        """应用现代化样式 - bluechips 专属设计"""
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f172a, stop:0.5 #1e293b, stop:1 #0f172a);
                margin: 0px;
                padding: 0px;
            }
            
            QWidget {
                background: transparent;
                margin: 0px;
                padding: 0px;
            }
            
            QGroupBox {
                font-weight: bold;
                font-size: 14px;
                border: none;
                border-radius: 16px;
                margin-top: 24px;
                margin-left: 0px;
                margin-right: 0px;
                margin-bottom: 0px;
                padding: 25px 15px 15px 15px;
                background-color: rgba(30, 41, 59, 0.95);
                color: #e2e8f0;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 15px;
                top: 8px;
                padding: 8px 20px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0ea5e9, stop:1 #06b6d4);
                color: white;
                font-size: 16px;
                font-weight: bold;
                border-radius: 10px;
            }
            
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0ea5e9, stop:1 #0284c7);
                color: white;
                border: none;
                border-radius: 12px;
                padding: 12px 24px;
                font-weight: bold;
                font-size: 13px;
                min-height: 20px;
                min-width: 80px;
            }
            
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #38bdf8, stop:1 #0ea5e9);
            }
            
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0284c7, stop:1 #0369a1);
            }
            
            QPushButton:disabled {
                background: #475569;
                color: #64748b;
            }
            
            QLineEdit {
                border: 2px solid #334155;
                border-radius: 12px;
                padding: 12px 16px;
                background-color: rgba(30, 41, 59, 0.9);
                font-size: 13px;
                color: #e2e8f0;
                selection-background-color: #0ea5e9;
            }
            
            QLineEdit:focus {
                background-color: #1e293b;
                border-color: #0ea5e9;
            }
            
            QLineEdit::placeholder {
                color: #64748b;
            }
            
            QComboBox {
                border: 2px solid #334155;
                border-radius: 12px;
                padding: 12px 16px;
                background-color: rgba(30, 41, 59, 0.9);
                font-size: 13px;
                min-width: 160px;
                color: #e2e8f0;
            }
            
            QComboBox:focus {
                background-color: #1e293b;
                border-color: #0ea5e9;
            }
            
            QComboBox::drop-down {
                border: none;
                width: 35px;
                border-top-right-radius: 12px;
                border-bottom-right-radius: 12px;
            }
            
            QComboBox::down-arrow {
                image: none;
                border-left: 6px solid transparent;
                border-right: 6px solid transparent;
                border-top: 8px solid #0ea5e9;
                margin-right: 12px;
            }
            
            QComboBox QAbstractItemView {
                border: none;
                border-radius: 12px;
                background-color: #1e293b;
                padding: 8px;
                selection-background-color: #0ea5e9;
                selection-color: white;
                color: #e2e8f0;
            }
            
            QTableWidget {
                background-color: rgba(30, 41, 59, 0.95);
                border: none;
                border-radius: 12px;
                gridline-color: #334155;
                font-size: 12px;
                color: #e2e8f0;
            }
            
            QTableWidget::item {
                padding: 12px 10px;
                border-bottom: 1px solid #334155;
                border-right: 1px solid #334155;
            }
            
            QTableWidget::item:selected {
                background-color: #0ea5e9;
                color: white;
            }
            
            QTableWidget::item:hover {
                background-color: #334155;
            }
            
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0ea5e9, stop:1 #0284c7);
                color: white;
                padding: 14px 10px;
                border: none;
                border-right: 2px solid rgba(255, 255, 255, 0.1);
                font-weight: bold;
                font-size: 12px;
            }
            
            QHeaderView::section:last {
                border-right: none;
            }
            
            QHeaderView::section:first {
                border-top-left-radius: 12px;
            }
            
            QHeaderView::section:last {
                border-top-right-radius: 12px;
            }
            
            QProgressBar {
                border: none;
                border-radius: 10px;
                text-align: center;
                background-color: #334155;
                height: 20px;
                font-weight: bold;
                font-size: 11px;
                color: #e2e8f0;
            }
            
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0ea5e9, stop:0.5 #06b6d4, stop:1 #14b8a6);
                border-radius: 10px;
            }
            
            QToolBar {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0f172a, stop:1 #1e293b);
                border: none;
                padding: 12px 15px;
                spacing: 10px;
            }
            
            QToolBar QToolButton {
                background-color: transparent;
                color: #94a3b8;
                border: none;
                border-radius: 12px;
                padding: 12px 20px;
                font-weight: bold;
                font-size: 13px;
                margin: 0 4px;
            }
            
            QToolBar QToolButton:hover {
                background-color: rgba(14, 165, 233, 0.15);
                color: #38bdf8;
            }
            
            QToolBar QToolButton:pressed {
                background-color: rgba(14, 165, 233, 0.25);
                color: #0ea5e9;
            }
            
            QStatusBar {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0f172a, stop:1 #1e293b);
                color: #94a3b8;
                font-size: 12px;
                padding: 8px 15px;
                border: none;
            }
            
            QScrollBar:vertical {
                border: none;
                background: transparent;
                width: 14px;
                margin: 4px;
            }
            
            QScrollBar::handle:vertical {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0ea5e9, stop:1 #06b6d4);
                border-radius: 7px;
                min-height: 40px;
            }
            
            QScrollBar::handle:vertical:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #38bdf8, stop:1 #0ea5e9);
            }
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: transparent;
            }
            
            QLabel {
                color: #94a3b8;
                font-size: 13px;
                background: transparent;
            }
            
            QCheckBox {
                spacing: 10px;
                font-size: 13px;
                color: #e2e8f0;
            }
            
            QCheckBox::indicator {
                width: 22px;
                height: 22px;
                border-radius: 6px;
                border: 2px solid #475569;
                background-color: #1e293b;
            }
            
            QCheckBox::indicator:hover {
                border-color: #0ea5e9;
            }
            
            QCheckBox::indicator:checked {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0ea5e9, stop:1 #06b6d4);
                border-color: #0ea5e9;
            }
            
            QSplitter::handle {
                background-color: #334155;
                height: 4px;
                border-radius: 2px;
            }
            
            QSplitter::handle:hover {
                background-color: #0ea5e9;
            }
            
            QMenu {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 8px;
            }
            
            QMenu::item {
                padding: 10px 30px;
                border-radius: 8px;
                color: #e2e8f0;
            }
            
            QMenu::item:selected {
                background-color: #0ea5e9;
                color: white;
            }
            
            QMessageBox {
                background-color: #1e293b;
                border-radius: 16px;
            }
            
            QMessageBox QLabel {
                color: #e2e8f0;
                font-size: 13px;
            }
            
            QMessageBox QPushButton {
                min-width: 80px;
            }
            
            QTreeWidget {
                background-color: rgba(30, 41, 59, 0.95);
                border: none;
                border-radius: 12px;
                font-size: 12px;
                color: #e2e8f0;
            }
            
            QTreeWidget::item {
                padding: 6px;
                border-bottom: 1px solid #334155;
            }
            
            QTreeWidget::item:selected {
                background-color: #0ea5e9;
                color: white;
            }
            
            QTreeWidget::item:hover:!selected {
                background-color: #334155;
            }
        """)
    
    def _play_entrance_animation(self):
        """播放窗口入场动画"""
        self.setWindowOpacity(0)
        
        opacity_anim = QPropertyAnimation(self, b"windowOpacity")
        opacity_anim.setDuration(400)
        opacity_anim.setStartValue(0.0)
        opacity_anim.setEndValue(1.0)
        opacity_anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
        
        geo = self.geometry()
        slide_anim = QPropertyAnimation(self, b"geometry")
        slide_anim.setDuration(500)
        slide_anim.setStartValue(
            geo.__class__(geo.x(), geo.y() + 30, geo.width(), geo.height())
        )
        slide_anim.setEndValue(geo)
        slide_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        group = QParallelAnimationGroup()
        group.addAnimation(opacity_anim)
        group.addAnimation(slide_anim)
        group.start()
        self._entrance_anim = group
    
    def _init_ui(self):
        """初始化用户界面"""
        central_widget = QWidget()
        central_widget.setContentsMargins(0, 0, 0, 0)
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        self._create_toolbar()
        
        import_panel = self._create_import_panel()
        main_layout.addWidget(import_panel)
        
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(4)
        
        interface_panel = self._create_interface_panel()
        splitter.addWidget(interface_panel)
        
        results_panel = self._create_results_panel()
        splitter.addWidget(results_panel)
        
        splitter.setSizes([350, 450])
        main_layout.addWidget(splitter)
        
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(f"✨ {APP_NAME} v{APP_VERSION} - by {APP_AUTHOR} | 就绪")
    
    def _create_toolbar(self):
        """创建工具栏"""
        toolbar = QToolBar("主工具栏")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)
        
        self.start_action = QAction("▶ 开始测试", self)
        self.start_action.setToolTip("开始测试选中的接口")
        toolbar.addAction(self.start_action)
        
        self.stop_action = QAction("⏹ 停止测试", self)
        self.stop_action.setToolTip("停止当前测试")
        toolbar.addAction(self.stop_action)
        
        toolbar.addSeparator()
        
        self.clear_action = QAction("🗑 清空结果", self)
        self.clear_action.setToolTip("清空测试结果")
        toolbar.addAction(self.clear_action)
        
        self.export_action = QAction("📊 导出结果", self)
        self.export_action.setToolTip("导出测试结果到文件")
        toolbar.addAction(self.export_action)
        
        toolbar.addSeparator()
        
        self.fuzzer_action = QAction("🎯 Fuzzer", self)
        self.fuzzer_action.setToolTip("参数变异测试")
        toolbar.addAction(self.fuzzer_action)
        
        self.settings_action = QAction("⚙ 设置", self)
        self.settings_action.setToolTip("打开设置对话框")
        toolbar.addAction(self.settings_action)
        
        self._style_toolbar_buttons(toolbar)
    
    def _style_toolbar_buttons(self, toolbar):
        """为工具栏按钮设置不同颜色"""
        buttons = {
            self.start_action: "#48bb78",
            self.stop_action: "#f56565",
            self.clear_action: "#ed8936",
            self.export_action: "#4299e1",
            self.fuzzer_action: "#f6ad55",
            self.settings_action: "#9f7aea"
        }
        
        for action, color in buttons.items():
            widget = toolbar.widgetForAction(action)
            if widget:
                widget.setStyleSheet(f"""
                    QToolButton {{
                        background: {color};
                        color: white;
                        border: none;
                        border-radius: 12px;
                        padding: 12px 20px;
                        font-weight: bold;
                        font-size: 13px;
                        margin: 0 4px;
                    }}
                    QToolButton:hover {{
                        background: {color};
                        border: 2px solid white;
                    }}
                    QToolButton:pressed {{
                        background: {color};
                        border: 2px solid rgba(255, 255, 255, 0.5);
                    }}
                """)
    
    def _create_import_panel(self):
        """创建导入面板"""
        panel = ModernGroupBox("📄 API 文档导入")
        layout = QHBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 30, 20, 20)
        
        type_label = QLabel("文档类型:")
        type_label.setStyleSheet("font-weight: bold; color: #94a3b8;")
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Swagger/OpenAPI", "ASP.NET Help Page", "🔍 API 自动发现"])
        
        url_label = QLabel("URL:")
        url_label.setStyleSheet("font-weight: bold; color: #94a3b8;")
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("输入 URL 或 JSON 文件路径...")
        
        self.file_button = QPushButton("📁 浏览")
        self.file_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #718096, stop:1 #4a5568);
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4a5568, stop:1 #2d3748);
            }
        """)
        
        self.import_button = QPushButton("🚀 导入")
        self.import_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #48bb78, stop:1 #38a169);
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #38a169, stop:1 #2f855a);
            }
        """)
        
        self.discover_button = QPushButton("🔍 发现 API")
        self.discover_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #f6ad55, stop:1 #dd6b20);
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #dd6b20, stop:1 #c05621);
            }
        """)
        
        self.import_progress = QProgressBar()
        self.import_progress.setVisible(False)
        self.import_progress.setFixedWidth(180)
        
        layout.addWidget(type_label)
        layout.addWidget(self.type_combo)
        layout.addWidget(url_label)
        layout.addWidget(self.url_input, 1)
        layout.addWidget(self.file_button)
        layout.addWidget(self.discover_button)
        layout.addWidget(self.import_button)
        layout.addWidget(self.import_progress)
        
        panel.setLayout(layout)
        return panel
    
    def _create_interface_panel(self):
        """创建接口列表面板"""
        panel = ModernGroupBox("📋 API 接口列表")
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(20, 30, 20, 20)
        
        self.interface_table = QTableWidget()
        self.interface_table.setColumnCount(6)
        self.interface_table.setHorizontalHeaderLabels([
            "选择", "方法", "URL", "描述", "标签", "状态"
        ])
        
        self.interface_table.setColumnWidth(0, 60)
        self.interface_table.setColumnWidth(1, 100)
        self.interface_table.setColumnWidth(2, 400)
        self.interface_table.setColumnWidth(3, 250)
        self.interface_table.setColumnWidth(4, 150)
        self.interface_table.setColumnWidth(5, 100)
        
        self.interface_table.setAlternatingRowColors(True)
        self.interface_table.setSortingEnabled(True)
        self.interface_table.verticalHeader().setVisible(False)
        self.interface_table.setShowGrid(False)
        
        layout.addWidget(self.interface_table)
        panel.setLayout(layout)
        return panel
    
    def _create_results_panel(self):
        """创建结果面板"""
        panel = ModernGroupBox("📊 测试结果")
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(20, 30, 20, 20)
        
        results_toolbar = QHBoxLayout()
        results_toolbar.setSpacing(15)
        
        proxy_label = QLabel("代理:")
        proxy_label.setStyleSheet("font-weight: bold; color: #4a5568;")
        
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("http://127.0.0.1:8080")
        self.proxy_input.setFixedWidth(200)
        
        status_label = QLabel("过滤状态码:")
        status_label.setStyleSheet("font-weight: bold; color: #4a5568;")
        
        self.status_input = QLineEdit()
        self.status_input.setPlaceholderText("404,500")
        self.status_input.setFixedWidth(150)
        
        self.apply_button = QPushButton("✓ 应用")
        self.apply_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #9f7aea, stop:1 #805ad5);
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #805ad5, stop:1 #6b46c1);
            }
        """)
        
        results_toolbar.addWidget(proxy_label)
        results_toolbar.addWidget(self.proxy_input)
        results_toolbar.addWidget(status_label)
        results_toolbar.addWidget(self.status_input)
        results_toolbar.addWidget(self.apply_button)
        results_toolbar.addStretch()
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(8)
        self.results_table.setHorizontalHeaderLabels([
            "ID", "方法", "URL", "状态码", "长度", "时间", "敏感信息", "操作"
        ])
        
        self.results_table.setColumnWidth(0, 60)
        self.results_table.setColumnWidth(1, 100)
        self.results_table.setColumnWidth(2, 400)
        self.results_table.setColumnWidth(3, 100)
        self.results_table.setColumnWidth(4, 100)
        self.results_table.setColumnWidth(5, 100)
        self.results_table.setColumnWidth(6, 100)
        self.results_table.setColumnWidth(7, 120)
        
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSortingEnabled(True)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setShowGrid(False)
        
        layout.addLayout(results_toolbar)
        layout.addWidget(self.results_table)
        panel.setLayout(layout)
        return panel
    
    def _init_signals(self):
        """初始化信号连接"""
        self.import_button.clicked.connect(self._on_import)
        self.discover_button.clicked.connect(self._on_discover)
        self.file_button.clicked.connect(self._on_browse_file)
        
        self.start_action.triggered.connect(self._on_start_test)
        self.stop_action.triggered.connect(self._on_stop_test)
        self.clear_action.triggered.connect(self._on_clear_results)
        self.export_action.triggered.connect(self._on_export_results)
        self.fuzzer_action.triggered.connect(self._on_fuzzer)
        self.settings_action.triggered.connect(self._on_settings)
        
        self.apply_button.clicked.connect(self._on_apply_filter)
        
        self.results_table.itemDoubleClicked.connect(self._on_result_double_click)
    
    def _on_import(self):
        """处理导入按钮点击"""
        doc_type = self.type_combo.currentText()
        url = self.url_input.text().strip()
        
        if not url:
            QMessageBox.warning(self, "⚠️ 提示", "请输入 URL 或文件路径")
            return
        
        if "自动发现" in doc_type:
            self._on_discover()
            return
        
        self.import_progress.setVisible(True)
        self.import_progress.setValue(0)
        self.status_bar.showMessage(f"⏳ 正在导入 {doc_type}...")
        
        self._animate_progress()
        
        try:
            if doc_type == "Swagger/OpenAPI":
                parser = SwaggerParser()
                self.endpoints = parser.parse_from_url(url)
            else:
                parser = AspNetParser()
                self.endpoints = parser.parse_from_url(url)
            
            self._populate_interface_table()
            self.import_progress.setValue(100)
            self.status_bar.showMessage(f"✅ 成功导入 {len(self.endpoints)} 个接口")
        except Exception as e:
            QMessageBox.critical(self, "❌ 错误", f"导入失败: {str(e)}")
            self.import_progress.setValue(0)
            self.status_bar.showMessage("❌ 导入失败")
        finally:
            self.import_progress.setVisible(False)
    
    def _on_discover(self):
        """处理 API 自动发现按钮点击"""
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "⚠️ 提示", "请输入目标 URL 进行 API 发现")
            return
        
        strategies, ok = QInputDialog.getItem(
            self, "🔍 API 自动发现",
            "选择发现策略:",
            ["全部策略", "仅爬取", "仅探测", "仅 JS 分析", "仅 Sitemap", "仅响应头"],
            0, False
        )
        if not ok:
            return
        
        strategy_map = {
            "全部策略": None,
            "仅爬取": ["crawl"],
            "仅探测": ["probe"],
            "仅 JS 分析": ["js"],
            "仅 Sitemap": ["sitemap"],
            "仅响应头": ["headers"],
        }
        
        self.import_progress.setVisible(True)
        self.import_progress.setValue(0)
        self.status_bar.showMessage(f"🔍 正在发现 API: {url}...")
        
        from src.parsers import APIDiscoverer
        
        self._discover_worker = _DiscoverWorker(
            url, strategy_map.get(strategies), timeout=15
        )
        self._discover_worker.progress_ready.connect(self._on_discover_progress)
        self._discover_worker.finished_ready.connect(self._on_discover_finished)
        self._discover_worker.start()
    
    def _on_discover_progress(self, message, progress):
        """发现进度更新"""
        self.status_bar.showMessage(message)
        self.import_progress.setValue(progress)
    
    def _on_discover_finished(self, endpoints):
        """发现完成"""
        self.import_progress.setVisible(False)
        
        if endpoints:
            self.endpoints = endpoints
            self._populate_interface_table()
            self.status_bar.showMessage(f"✅ API 发现完成: 找到 {len(endpoints)} 个接口")
            QMessageBox.information(
                self, "🔍 发现完成",
                f"API 自动发现完成！\n\n"
                f"发现接口数量: {len(endpoints)}\n\n"
                f"请在接口列表中查看并选择要测试的接口。"
            )
        else:
            self.status_bar.showMessage("⚠️ 未发现 API 接口")
            QMessageBox.information(
                self, "🔍 发现结果",
                "未发现 API 接口。\n\n"
                "建议：\n"
                "1. 确认目标 URL 正确\n"
                "2. 尝试使用「全部策略」\n"
                "3. 检查目标是否可访问"
            )
    
    def _animate_progress(self):
        """进度条动画"""
        for i in range(0, 90, 10):
            self.import_progress.setValue(i)
    
    def _on_browse_file(self):
        """处理浏览文件按钮点击"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self, "选择 API 文档文件", "", "JSON 文件;;所有文件"
        )
        if file_path:
            self.url_input.setText(file_path)
    
    def _populate_interface_table(self):
        """填充接口表格"""
        self.interface_table.setRowCount(0)
        
        for i, endpoint in enumerate(self.endpoints):
            row_position = self.interface_table.rowCount()
            self.interface_table.insertRow(row_position)
            
            checkbox = QCheckBox()
            self.interface_table.setCellWidget(row_position, 0, checkbox)
            
            method_item = QTableWidgetItem(endpoint.method)
            method_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            if endpoint.method == "GET":
                method_item.setBackground(QColor(72, 187, 120))
                method_item.setForeground(QColor(255, 255, 255))
            elif endpoint.method == "POST":
                method_item.setBackground(QColor(66, 153, 225))
                method_item.setForeground(QColor(255, 255, 255))
            elif endpoint.method == "PUT":
                method_item.setBackground(QColor(236, 201, 75))
                method_item.setForeground(QColor(45, 55, 72))
            elif endpoint.method == "DELETE":
                method_item.setBackground(QColor(245, 101, 101))
                method_item.setForeground(QColor(255, 255, 255))
            elif endpoint.method == "PATCH":
                method_item.setBackground(QColor(159, 122, 234))
                method_item.setForeground(QColor(255, 255, 255))
            
            self.interface_table.setItem(row_position, 1, method_item)
            self.interface_table.setItem(row_position, 2, QTableWidgetItem(endpoint.url))
            self.interface_table.setItem(row_position, 3, QTableWidgetItem(endpoint.description))
            
            tags = ", ".join(endpoint.tags) if endpoint.tags else ""
            self.interface_table.setItem(row_position, 4, QTableWidgetItem(tags))
            
            status_item = QTableWidgetItem("✓ 就绪")
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            status_item.setForeground(QColor(72, 187, 120))
            self.interface_table.setItem(row_position, 5, status_item)
    
    def _on_start_test(self):
        """处理开始测试按钮点击"""
        selected_endpoints = []
        for row in range(self.interface_table.rowCount()):
            checkbox = self.interface_table.cellWidget(row, 0)
            if checkbox and checkbox.isChecked():
                selected_endpoints.append(self.endpoints[row])
        
        if not selected_endpoints:
            QMessageBox.warning(self, "⚠️ 提示", "请至少选择一个接口")
            return
        
        if self.safe_mode.is_safe_mode_enabled():
            original_count = len(selected_endpoints)
            selected_endpoints = self.safe_mode.filter_endpoints(selected_endpoints)
            filtered_count = original_count - len(selected_endpoints)
            if filtered_count > 0:
                self.status_bar.showMessage(
                    f"🛡️ 安全模式过滤: 移除 {filtered_count} 个不安全接口，"
                    f"保留 {len(selected_endpoints)} 个"
                )
            if not selected_endpoints:
                QMessageBox.warning(
                    self, "⚠️ 安全模式",
                    "所有选中接口均被安全模式过滤，请调整安全设置或选择其他接口"
                )
                return
        
        proxy = self.proxy_input.text().strip()
        if proxy:
            self.http_client.set_proxy(proxy)
            self.test_executor.set_proxy(proxy)
        
        status_codes = self.status_input.text().strip()
        if status_codes:
            try:
                codes = [int(code.strip()) for code in status_codes.split(",")]
                self.deduplicator.set_filter_status_codes(codes)
            except ValueError:
                QMessageBox.warning(self, "⚠️ 提示", "状态码格式无效")
        
        self.test_results = []
        self.results_table.setRowCount(0)
        self.status_bar.showMessage(f"🚀 正在测试 {len(selected_endpoints)} 个接口...")
        
        self._test_worker = TestWorker(self.test_executor, selected_endpoints)
        self._test_worker.result_ready.connect(self._on_single_result)
        self._test_worker.progress.connect(self._on_test_progress)
        self._test_worker.finished_all.connect(self._on_test_finished)
        self._test_worker.error_occurred.connect(self._on_test_error)
        self._test_worker.start()
    
    def _on_single_result(self, result):
        """单个测试结果就绪"""
        self.test_results.append(result)
        self._add_result_row(result, self.results_table.rowCount())
    
    def _on_test_progress(self, completed, total):
        """测试进度更新"""
        self.status_bar.showMessage(f"🔄 测试进度: {completed}/{total}")
    
    def _on_test_finished(self, results):
        """所有测试完成"""
        self.test_results = self.deduplicator.deduplicate(self.test_results)
        self._populate_results_table()
        self.status_bar.showMessage(f"✅ 测试完成: {len(self.test_results)} 个结果")
    
    def _on_test_error(self, error_msg):
        """测试出错"""
        self.status_bar.showMessage(f"❌ 测试出错: {error_msg}")
    
    def _on_stop_test(self):
        """处理停止测试按钮点击"""
        stopped = False
        if hasattr(self, '_test_worker') and self._test_worker.isRunning():
            self._test_worker.stop()
            self._test_worker.wait(3000)
            stopped = True
        if hasattr(self, '_fuzz_worker') and self._fuzz_worker.isRunning():
            self._fuzz_worker.stop()
            self._fuzz_worker.wait(3000)
            stopped = True
        if stopped:
            self.status_bar.showMessage("⏹ 测试已停止")
        else:
            self.status_bar.showMessage("⏹ 没有正在运行的测试")
    
    def _on_clear_results(self):
        """处理清空结果按钮点击"""
        self.results_table.setRowCount(0)
        self.test_results = []
        self.status_bar.showMessage("🗑 结果已清空")
    
    def _on_export_results(self):
        """处理导出结果按钮点击"""
        if not self.test_results:
            QMessageBox.warning(self, "⚠️ 提示", "没有可导出的结果")
            return
        
        format_choice, ok = QInputDialog.getItem(
            self, "📊 导出格式",
            "选择导出格式:",
            ["Excel (.xlsx)", "CSV (.csv)", "JSON (.json)", "HTML (.html)"],
            0, False
        )
        if not ok:
            return
        
        ext_map = {
            "Excel (.xlsx)": (".xlsx", "Excel 文件 (*.xlsx)"),
            "CSV (.csv)": (".csv", "CSV 文件 (*.csv)"),
            "JSON (.json)": (".json", "JSON 文件 (*.json)"),
            "HTML (.html)": (".html", "HTML 文件 (*.html)")
        }
        ext, filter_str = ext_map[format_choice]
        
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(
            self, "导出结果", f"{APP_NAME}_results{ext}", filter_str
        )
        
        if file_path:
            from src.engines import Exporter
            exporter = Exporter()
            try:
                if format_choice.startswith("Excel"):
                    exporter.export_to_excel(self.test_results, file_path)
                elif format_choice.startswith("CSV"):
                    exporter.export_to_csv(self.test_results, file_path)
                elif format_choice.startswith("JSON"):
                    exporter.export_to_json(self.test_results, file_path)
                elif format_choice.startswith("HTML"):
                    exporter.export_to_html(self.test_results, file_path)
                QMessageBox.information(self, "✅ 成功", f"结果已导出到: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "❌ 错误", f"导出失败: {str(e)}")
    
    def _on_settings(self):
        """处理设置按钮点击"""
        from src.ui import SettingsDialog
        dialog = SettingsDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._rebuild_test_executor()
    
    def _rebuild_test_executor(self):
        """根据设置重建 TestExecutor"""
        import json
        try:
            with open('config/settings.json', 'r', encoding='utf-8') as f:
                settings = json.load(f)
            self.test_executor = TestExecutor(
                enable_sensitive_detection=settings.get("enable_sensitive_detection", True),
                enable_jwt_detection=settings.get("enable_jwt_detection", True),
                enable_idor_detection=settings.get("enable_idor_detection", False),
                enable_auth_bypass_detection=settings.get("enable_auth_bypass_detection", False),
                enable_upload_detection=settings.get("enable_upload_detection", False)
            )
            self.status_bar.showMessage("✅ 检测器设置已更新")
        except Exception as e:
            self.status_bar.showMessage(f"⚠️ 更新检测器设置失败: {e}")
    
    def _on_fuzzer(self):
        """处理 Fuzzer 按钮点击"""
        selected_endpoints = []
        for row in range(self.interface_table.rowCount()):
            checkbox = self.interface_table.cellWidget(row, 0)
            if checkbox and checkbox.isChecked():
                selected_endpoints.append(self.endpoints[row])
        
        if not selected_endpoints:
            QMessageBox.warning(self, "⚠️ 提示", "请先选择要 Fuzzing 的接口")
            return
        
        from src.engines import Fuzzer
        fuzzer = Fuzzer()
        
        categories, ok = QInputDialog.getItem(
            self, "🎯 Fuzzer 设置",
            "选择 Payload 类别:",
            ["all", "sqli", "xss", "path_traversal", "command_injection"],
            0, False
        )
        if not ok:
            return
        
        proxy = self.proxy_input.text().strip()
        if proxy:
            fuzzer.set_proxy(proxy)
        
        category = None if categories == "all" else categories
        
        self.test_results = []
        self.results_table.setRowCount(0)
        self.status_bar.showMessage(f"🎯 正在 Fuzzing {len(selected_endpoints)} 个接口...")
        
        self._fuzz_worker = _FuzzWorker(fuzzer, selected_endpoints, self.http_client, category)
        self._fuzz_worker.result_ready.connect(self._on_single_result)
        self._fuzz_worker.progress.connect(self._on_test_progress)
        self._fuzz_worker.finished_all.connect(self._on_fuzz_finished)
        self._fuzz_worker.error_occurred.connect(self._on_test_error)
        self._fuzz_worker.start()
    
    def _on_fuzz_finished(self, results):
        """Fuzzing 完成"""
        self.test_results = self.deduplicator.deduplicate(self.test_results)
        self._populate_results_table()
        self.status_bar.showMessage(f"✅ Fuzzing 完成: {len(self.test_results)} 个结果")
    
    def _on_apply_filter(self):
        """处理应用过滤按钮点击"""
        status_filter = self.status_input.text().strip()
        if status_filter:
            try:
                codes = [int(c.strip()) for c in status_filter.split(",")]
                filtered = [r for r in self.test_results if r.response_status in codes]
                self.results_table.setRowCount(0)
                for result in filtered:
                    self._add_result_row(result, self.results_table.rowCount())
                self.status_bar.showMessage(f"✅ 过滤完成: 显示 {len(filtered)} 个结果")
            except ValueError:
                self.status_bar.showMessage("⚠️ 状态码格式无效")
        else:
            self._populate_results_table()
            self.status_bar.showMessage("✅ 过滤已清除")
    
    def _on_result_double_click(self, item):
        """处理结果双击"""
        row = item.row()
        result = self.test_results[row]
        self._show_result_details(result)
    
    def _populate_results_table(self):
        """填充结果表格"""
        self.results_table.setRowCount(0)
        
        for i, result in enumerate(self.test_results):
            self._add_result_row(result, i)
    
    def _add_result_row(self, result, index):
        """添加单行结果到表格"""
        row_position = self.results_table.rowCount()
        self.results_table.insertRow(row_position)
        
        self.results_table.setItem(row_position, 0, QTableWidgetItem(str(index + 1)))
        
        method_item = QTableWidgetItem(result.endpoint.method)
        method_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_table.setItem(row_position, 1, method_item)
        
        self.results_table.setItem(row_position, 2, QTableWidgetItem(result.endpoint.url))
        
        status_item = QTableWidgetItem(str(result.response_status))
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        
        if 200 <= result.response_status < 300:
            status_item.setBackground(QColor(72, 187, 120))
            status_item.setForeground(QColor(255, 255, 255))
        elif 400 <= result.response_status < 500:
            status_item.setBackground(QColor(236, 201, 75))
            status_item.setForeground(QColor(45, 55, 72))
        elif 500 <= result.response_status < 600:
            status_item.setBackground(QColor(245, 101, 101))
            status_item.setForeground(QColor(255, 255, 255))
        
        self.results_table.setItem(row_position, 3, status_item)
        
        length_item = QTableWidgetItem(str(result.response_length))
        length_item.setTextAlignment(Qt.AlignmentFlag.AlignRight)
        self.results_table.setItem(row_position, 4, length_item)
        
        time_item = QTableWidgetItem(f"{result.response_time:.2f}s")
        time_item.setTextAlignment(Qt.AlignmentFlag.AlignRight)
        self.results_table.setItem(row_position, 5, time_item)
        
        sensitive_count = len(result.sensitive_info)
        sensitive_item = QTableWidgetItem(str(sensitive_count))
        sensitive_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        
        if sensitive_count > 0:
            sensitive_item.setBackground(QColor(245, 101, 101))
            sensitive_item.setForeground(QColor(255, 255, 255))
        
        self.results_table.setItem(row_position, 6, sensitive_item)
        
        view_button = QPushButton("🔍 查看")
        view_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0ea5e9, stop:1 #0284c7);
                padding: 6px 12px;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #38bdf8, stop:1 #0ea5e9);
            }
        """)
        view_button.clicked.connect(lambda _, r=result: self._show_result_details(r))
        self.results_table.setCellWidget(row_position, 7, view_button)
    
    def _show_result_details(self, result):
        """显示结果详情"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"🔍 结果详情 - {APP_NAME}")
        dialog.setGeometry(200, 200, 900, 700)
        dialog.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f172a, stop:0.5 #1e293b, stop:1 #0f172a);
            }
            QTextEdit {
                border: 2px solid #334155;
                border-radius: 12px;
                padding: 15px;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 12px;
                background-color: rgba(30, 41, 59, 0.95);
                color: #e2e8f0;
            }
            QLabel {
                font-weight: bold;
                font-size: 14px;
                color: #e2e8f0;
                background: transparent;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0ea5e9, stop:1 #0284c7);
                color: white;
                border: none;
                border-radius: 12px;
                padding: 12px 35px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #38bdf8, stop:1 #0ea5e9);
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        request_text = QTextEdit()
        request_text.setReadOnly(True)
        request_text.setText(f"请求:\n{result.request_headers}\n\n{result.request_body}")
        
        response_text = QTextEdit()
        response_text.setReadOnly(True)
        response_text.setText(f"响应:\n状态码: {result.response_status}\n长度: {result.response_length}\n时间: {result.response_time:.2f}s\n\n{result.response_body}")
        
        sensitive_text = QTextEdit()
        sensitive_text.setReadOnly(True)
        if result.sensitive_info:
            sensitive_info = "\n".join([f"{info.rule_name}: {info.matched_content}" for info in result.sensitive_info])
            sensitive_text.setText(f"敏感信息:\n{sensitive_info}")
        else:
            sensitive_text.setText("敏感信息: 无")
        
        layout.addWidget(QLabel("📤 请求"))
        layout.addWidget(request_text)
        layout.addWidget(QLabel("📥 响应"))
        layout.addWidget(response_text)
        layout.addWidget(QLabel("🔐 敏感信息"))
        layout.addWidget(sensitive_text)
        
        close_button = QPushButton("✓ 关闭")
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button, alignment=Qt.AlignmentFlag.AlignCenter)
        
        dialog.setLayout(layout)
        dialog.exec()
