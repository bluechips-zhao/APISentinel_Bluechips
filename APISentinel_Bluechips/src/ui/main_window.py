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
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve, QSize
from PyQt6.QtGui import QIcon, QColor, QFont, QAction, QPalette, QLinearGradient, QPainter

from src.parsers import SwaggerParser, AspNetParser
from src.engines import TestExecutor, Deduplicator, SafeMode
from src.core.models import APIEndpoint
from src.core.http_client import HttpClient


APP_NAME = "APISentinel_Bluechips"
APP_AUTHOR = "bluechips"
APP_VERSION = "1.0.0"


class ModernButton(QPushButton):
    """现代化按钮 - bluechips 设计"""
    
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._opacity = 1.0
        
    def enterEvent(self, event):
        self.animate_opacity(0.85)
        super().enterEvent(event)
    
    def leaveEvent(self, event):
        self.animate_opacity(1.0)
        super().leaveEvent(event)
    
    def animate_opacity(self, value):
        self._opacity = value
        self.update()


class ModernGroupBox(QGroupBox):
    """现代化分组框 - 无边框阴影效果"""
    
    def __init__(self, title="", parent=None):
        super().__init__(title, parent)
        self._setup_shadow()
    
    def _setup_shadow(self):
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 30))
        shadow.setOffset(0, 4)
        self.setGraphicsEffect(shadow)


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
        gradient.setColorAt(0, QColor(102, 126, 234))
        gradient.setColorAt(0.5, QColor(118, 75, 162))
        gradient.setColorAt(1, QColor(240, 147, 251))
        
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
                    stop:0 #667eea, stop:0.5 #764ba2, stop:1 #f093fb);
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
                background-color: rgba(255, 255, 255, 0.95);
                color: #2d3748;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 15px;
                top: 8px;
                padding: 8px 20px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #667eea, stop:1 #764ba2);
                color: white;
                font-size: 16px;
                font-weight: bold;
                border-radius: 10px;
            }
            
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #667eea, stop:1 #764ba2);
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
                    stop:0 #5a67d8, stop:1 #6b46c1);
            }
            
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4c51bf, stop:1 #553c9a);
            }
            
            QPushButton:disabled {
                background: #cbd5e0;
                color: #a0aec0;
            }
            
            QLineEdit {
                border: none;
                border-radius: 12px;
                padding: 12px 16px;
                background-color: rgba(255, 255, 255, 0.9);
                font-size: 13px;
                color: #2d3748;
                selection-background-color: #667eea;
            }
            
            QLineEdit:focus {
                background-color: white;
            }
            
            QLineEdit::placeholder {
                color: #a0aec0;
            }
            
            QComboBox {
                border: none;
                border-radius: 12px;
                padding: 12px 16px;
                background-color: rgba(255, 255, 255, 0.9);
                font-size: 13px;
                min-width: 160px;
                color: #2d3748;
            }
            
            QComboBox:focus {
                background-color: white;
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
                border-top: 8px solid #667eea;
                margin-right: 12px;
            }
            
            QComboBox QAbstractItemView {
                border: none;
                border-radius: 12px;
                background-color: white;
                padding: 8px;
                selection-background-color: #667eea;
                selection-color: white;
            }
            
            QTableWidget {
                background-color: rgba(255, 255, 255, 0.95);
                border: none;
                border-radius: 12px;
                gridline-color: #e2e8f0;
                font-size: 12px;
                color: #2d3748;
            }
            
            QTableWidget::item {
                padding: 12px 10px;
                border-bottom: 1px solid #e2e8f0;
                border-right: 1px solid #e2e8f0;
            }
            
            QTableWidget::item:selected {
                background-color: #667eea;
                color: white;
            }
            
            QTableWidget::item:hover {
                background-color: #f7fafc;
            }
            
            QHeaderView::section {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #667eea, stop:1 #764ba2);
                color: white;
                padding: 14px 10px;
                border: none;
                border-right: 2px solid rgba(255, 255, 255, 0.3);
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
                background-color: rgba(255, 255, 255, 0.5);
                height: 20px;
                font-weight: bold;
                font-size: 11px;
                color: #4a5568;
            }
            
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #48bb78, stop:0.5 #38b2ac, stop:1 #4299e1);
                border-radius: 10px;
            }
            
            QToolBar {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a202c, stop:1 #2d3748);
                border: none;
                padding: 12px 15px;
                spacing: 10px;
            }
            
            QToolBar QToolButton {
                background-color: transparent;
                color: white;
                border: none;
                border-radius: 12px;
                padding: 12px 20px;
                font-weight: bold;
                font-size: 13px;
                margin: 0 4px;
            }
            
            QToolBar QToolButton:hover {
                background-color: rgba(255, 255, 255, 0.15);
            }
            
            QToolBar QToolButton:pressed {
                background-color: rgba(255, 255, 255, 0.25);
            }
            
            QStatusBar {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a202c, stop:1 #2d3748);
                color: white;
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
                    stop:0 #667eea, stop:1 #764ba2);
                border-radius: 7px;
                min-height: 40px;
            }
            
            QScrollBar::handle:vertical:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #5a67d8, stop:1 #6b46c1);
            }
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: transparent;
            }
            
            QLabel {
                color: #4a5568;
                font-size: 13px;
                background: transparent;
            }
            
            QCheckBox {
                spacing: 10px;
                font-size: 13px;
                color: #2d3748;
            }
            
            QCheckBox::indicator {
                width: 22px;
                height: 22px;
                border-radius: 6px;
                border: 2px solid #cbd5e0;
                background-color: white;
            }
            
            QCheckBox::indicator:hover {
                border-color: #667eea;
            }
            
            QCheckBox::indicator:checked {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #667eea, stop:1 #764ba2);
                border-color: #667eea;
            }
            
            QSplitter::handle {
                background-color: rgba(255, 255, 255, 0.3);
                height: 4px;
                border-radius: 2px;
            }
            
            QSplitter::handle:hover {
                background-color: rgba(102, 126, 234, 0.8);
            }
            
            QMenu {
                background-color: white;
                border: none;
                border-radius: 12px;
                padding: 8px;
            }
            
            QMenu::item {
                padding: 10px 30px;
                border-radius: 8px;
                color: #2d3748;
            }
            
            QMenu::item:selected {
                background-color: #667eea;
                color: white;
            }
            
            QMessageBox {
                background-color: white;
                border-radius: 16px;
            }
            
            QMessageBox QLabel {
                color: #2d3748;
                font-size: 13px;
            }
            
            QMessageBox QPushButton {
                min-width: 80px;
            }
        """)
    
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
        type_label.setStyleSheet("font-weight: bold; color: #4a5568;")
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Swagger/OpenAPI", "ASP.NET Help Page"])
        
        url_label = QLabel("URL:")
        url_label.setStyleSheet("font-weight: bold; color: #4a5568;")
        
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
        
        self.import_progress = QProgressBar()
        self.import_progress.setVisible(False)
        self.import_progress.setFixedWidth(180)
        
        layout.addWidget(type_label)
        layout.addWidget(self.type_combo)
        layout.addWidget(url_label)
        layout.addWidget(self.url_input, 1)
        layout.addWidget(self.file_button)
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
        self.file_button.clicked.connect(self._on_browse_file)
        
        self.start_action.triggered.connect(self._on_start_test)
        self.stop_action.triggered.connect(self._on_stop_test)
        self.clear_action.triggered.connect(self._on_clear_results)
        self.export_action.triggered.connect(self._on_export_results)
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
        
        proxy = self.proxy_input.text().strip()
        if proxy:
            self.http_client.set_proxy(proxy)
        
        status_codes = self.status_input.text().strip()
        if status_codes:
            try:
                codes = [int(code.strip()) for code in status_codes.split(",")]
                self.deduplicator.set_filter_status_codes(codes)
            except ValueError:
                QMessageBox.warning(self, "⚠️ 提示", "状态码格式无效")
        
        self.status_bar.showMessage(f"🚀 正在测试 {len(selected_endpoints)} 个接口...")
        
        try:
            self.test_results = self.test_executor.execute_all(selected_endpoints, max_workers=5)
            self.test_results = self.deduplicator.deduplicate(self.test_results)
            
            self._populate_results_table()
            self.status_bar.showMessage(f"✅ 测试完成: {len(self.test_results)} 个结果")
        except Exception as e:
            QMessageBox.critical(self, "❌ 错误", f"测试失败: {str(e)}")
            self.status_bar.showMessage("❌ 测试失败")
    
    def _on_stop_test(self):
        """处理停止测试按钮点击"""
        self.status_bar.showMessage("⏹ 测试已停止")
    
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
        
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(
            self, "导出结果", f"{APP_NAME}_results.xlsx", "Excel 文件 (*.xlsx)"
        )
        
        if file_path:
            from src.engines import Exporter
            exporter = Exporter()
            try:
                exporter.export_to_excel(self.test_results, file_path)
                QMessageBox.information(self, "✅ 成功", f"结果已导出到: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "❌ 错误", f"导出失败: {str(e)}")
    
    def _on_settings(self):
        """处理设置按钮点击"""
        from src.ui import SettingsDialog
        dialog = SettingsDialog(self)
        dialog.exec()
    
    def _on_apply_filter(self):
        """处理应用过滤按钮点击"""
        self.status_bar.showMessage("✓ 过滤已应用")
    
    def _on_result_double_click(self, item):
        """处理结果双击"""
        row = item.row()
        result = self.test_results[row]
        self._show_result_details(result)
    
    def _populate_results_table(self):
        """填充结果表格"""
        self.results_table.setRowCount(0)
        
        for i, result in enumerate(self.test_results):
            row_position = self.results_table.rowCount()
            self.results_table.insertRow(row_position)
            
            self.results_table.setItem(row_position, 0, QTableWidgetItem(str(i + 1)))
            
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
                        stop:0 #667eea, stop:1 #764ba2);
                    padding: 6px 12px;
                    border-radius: 8px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #5a67d8, stop:1 #6b46c1);
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
                    stop:0 #667eea, stop:0.5 #764ba2, stop:1 #f093fb);
            }
            QTextEdit {
                border: none;
                border-radius: 12px;
                padding: 15px;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 12px;
                background-color: rgba(255, 255, 255, 0.95);
                color: #2d3748;
            }
            QLabel {
                font-weight: bold;
                font-size: 14px;
                color: white;
                background: transparent;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #48bb78, stop:1 #38a169);
                color: white;
                border: none;
                border-radius: 12px;
                padding: 12px 35px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #38a169, stop:1 #2f855a);
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
