"""
APISentinel_Bluechips - 设置对话框
Author: bluechips
Version: 1.1.0
"""

from PyQt6.QtWidgets import (
    QDialog, QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QTabWidget,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QListWidget, QListWidgetItem, QTextEdit, QCheckBox, QComboBox,
    QInputDialog, QFileDialog, QMessageBox, QSpinBox, QDoubleSpinBox,
    QScrollArea, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve, QParallelAnimationGroup
from PyQt6.QtGui import QColor
import json
import os

from src.engines import sensitive_rule_library, Fuzzer, SafeMode
from src.ui.main_window import APP_NAME, APP_AUTHOR, APP_VERSION


class ModernGroupBox(QGroupBox):
    """现代化分组框 - 无边框阴影效果"""
    
    def __init__(self, title="", parent=None):
        super().__init__(title, parent)
        self._setup_shadow()
    
    def _setup_shadow(self):
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 0, 0, 25))
        shadow.setOffset(0, 3)
        self.setGraphicsEffect(shadow)


class SettingsDialog(QDialog):
    """设置对话框 - APISentinel_Bluechips by bluechips"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"⚙ 设置 - {APP_NAME}")
        self.setGeometry(200, 200, 950, 750)
        
        self.settings_file = "config/settings.json"
        self.settings = self._load_settings()
        
        self.fuzzer = Fuzzer()
        self.safe_mode = SafeMode()
        
        self._apply_modern_style()
        
        self._init_ui()
        self._play_entrance_animation()
    
    def _apply_modern_style(self):
        """应用现代化样式 - bluechips 专属设计"""
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f172a, stop:0.5 #1e293b, stop:1 #0f172a);
            }
            
            QTabWidget::pane {
                border: none;
                border-radius: 16px;
                background-color: rgba(30, 41, 59, 0.95);
                padding: 15px;
            }
            
            QTabBar::tab {
                background-color: rgba(51, 65, 85, 0.5);
                color: #94a3b8;
                padding: 14px 28px;
                margin-right: 6px;
                border-top-left-radius: 12px;
                border-top-right-radius: 12px;
                font-weight: bold;
                font-size: 13px;
            }
            
            QTabBar::tab:selected {
                background-color: rgba(30, 41, 59, 0.95);
                color: #0ea5e9;
            }
            
            QTabBar::tab:hover:!selected {
                background-color: rgba(51, 65, 85, 0.8);
                color: #e2e8f0;
            }
            
            QGroupBox {
                font-weight: bold;
                font-size: 13px;
                border: none;
                border-radius: 12px;
                margin-top: 22px;
                padding: 22px 15px 15px 15px;
                background-color: rgba(30, 41, 59, 0.9);
                color: #e2e8f0;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 12px;
                top: 6px;
                padding: 6px 16px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0ea5e9, stop:1 #06b6d4);
                color: white;
                font-size: 14px;
                font-weight: bold;
                border-radius: 8px;
            }
            
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0ea5e9, stop:1 #0284c7);
                color: white;
                border: none;
                border-radius: 10px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 12px;
                min-height: 18px;
            }
            
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #38bdf8, stop:1 #0ea5e9);
            }
            
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0284c7, stop:1 #0369a1);
            }
            
            QLineEdit {
                border: 2px solid #334155;
                border-radius: 10px;
                padding: 10px 14px;
                background-color: rgba(30, 41, 59, 0.9);
                font-size: 12px;
                color: #e2e8f0;
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
                border-radius: 10px;
                padding: 10px 14px;
                background-color: rgba(30, 41, 59, 0.9);
                font-size: 12px;
                color: #e2e8f0;
            }
            
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 7px solid #0ea5e9;
                margin-right: 10px;
            }
            
            QComboBox QAbstractItemView {
                border: none;
                border-radius: 10px;
                background-color: #1e293b;
                padding: 5px;
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
                padding: 8px;
                border-bottom: 1px solid #334155;
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
                padding: 10px;
                border: none;
                font-weight: bold;
                font-size: 11px;
            }
            
            QListWidget {
                background-color: rgba(30, 41, 59, 0.95);
                border: none;
                border-radius: 12px;
                padding: 8px;
                font-size: 12px;
                color: #e2e8f0;
            }
            
            QListWidget::item {
                padding: 10px 12px;
                border-radius: 8px;
                margin: 2px 0;
            }
            
            QListWidget::item:selected {
                background-color: #0ea5e9;
                color: white;
            }
            
            QListWidget::item:hover:!selected {
                background-color: #334155;
            }
            
            QTextEdit {
                background-color: rgba(30, 41, 59, 0.95);
                border: 2px solid #334155;
                border-radius: 10px;
                padding: 10px;
                font-size: 12px;
                color: #e2e8f0;
            }
            
            QTextEdit:focus {
                background-color: #1e293b;
                border-color: #0ea5e9;
            }
            
            QCheckBox {
                spacing: 10px;
                font-size: 12px;
                color: #e2e8f0;
            }
            
            QCheckBox::indicator {
                width: 20px;
                height: 20px;
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
            
            QScrollBar:vertical {
                border: none;
                background: transparent;
                width: 12px;
                margin: 3px;
            }
            
            QScrollBar::handle:vertical {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0ea5e9, stop:1 #06b6d4);
                border-radius: 6px;
                min-height: 35px;
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
                font-size: 12px;
                background: transparent;
            }
            
            QSpinBox, QDoubleSpinBox {
                border: 2px solid #334155;
                border-radius: 10px;
                padding: 8px 12px;
                background-color: rgba(30, 41, 59, 0.9);
                font-size: 12px;
                color: #e2e8f0;
            }
            
            QSpinBox:focus, QDoubleSpinBox:focus {
                background-color: #1e293b;
                border-color: #0ea5e9;
            }
        """)
    
    def _play_entrance_animation(self):
        """播放对话框入场动画"""
        self.setWindowOpacity(0)
        
        opacity_anim = QPropertyAnimation(self, b"windowOpacity")
        opacity_anim.setDuration(300)
        opacity_anim.setStartValue(0.0)
        opacity_anim.setEndValue(1.0)
        opacity_anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
        
        geo = self.geometry()
        slide_anim = QPropertyAnimation(self, b"geometry")
        slide_anim.setDuration(400)
        slide_anim.setStartValue(
            geo.__class__(geo.x(), geo.y() + 20, geo.width(), geo.height())
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
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        title_label = QLabel(f"⚙ {APP_NAME} 设置")
        title_label.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: white;
            padding: 5px;
        """)
        main_layout.addWidget(title_label)
        
        self.tab_widget = QTabWidget()
        self.tab_widget.setIconSize(QSize(20, 20))
        
        self.tab_widget.addTab(self._create_sensitive_rules_tab(), "🔐 敏感规则")
        self.tab_widget.addTab(self._create_headers_tab(), "📋 请求头")
        self.tab_widget.addTab(self._create_fuzzing_tab(), "🎯 变异测试")
        self.tab_widget.addTab(self._create_safety_tab(), "🛡️ 安全设置")
        self.tab_widget.addTab(self._create_disclaimer_tab(), "📜 免责声明")
        
        main_layout.addWidget(self.tab_widget)
        
        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)
        
        self.save_button = QPushButton("💾 保存")
        self.save_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #48bb78, stop:1 #38a169);
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #38a169, stop:1 #2f855a);
            }
        """)
        self.save_button.clicked.connect(self._on_save)
        
        self.apply_button = QPushButton("✓ 应用")
        self.apply_button.clicked.connect(self._on_apply)
        
        self.reset_button = QPushButton("🔄 重置")
        self.reset_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ed8936, stop:1 #dd6b20);
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #dd6b20, stop:1 #c05621);
            }
        """)
        self.reset_button.clicked.connect(self._on_reset)
        
        self.cancel_button = QPushButton("✕ 取消")
        self.cancel_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #718096, stop:1 #4a5568);
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4a5568, stop:1 #2d3748);
            }
        """)
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.apply_button)
        button_layout.addWidget(self.reset_button)
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_button)
        
        main_layout.addLayout(button_layout)
        
        footer_label = QLabel(f"Made with ❤️ by {APP_AUTHOR} | v{APP_VERSION}")
        footer_label.setStyleSheet("""
            font-size: 11px;
            color: rgba(255, 255, 255, 0.7);
            padding: 3px;
        """)
        footer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(footer_label)
    
    def _create_sensitive_rules_tab(self):
        """创建敏感规则标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(12)
        layout.setContentsMargins(10, 15, 10, 10)
        
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(5)
        self.rules_table.setHorizontalHeaderLabels([
            "启用", "规则名称", "正则表达式", "风险等级", "分类"
        ])
        
        self.rules_table.setColumnWidth(0, 60)
        self.rules_table.setColumnWidth(1, 180)
        self.rules_table.setColumnWidth(2, 280)
        self.rules_table.setColumnWidth(3, 100)
        self.rules_table.setColumnWidth(4, 120)
        
        self.rules_table.setAlternatingRowColors(True)
        self.rules_table.setSortingEnabled(True)
        self.rules_table.verticalHeader().setVisible(False)
        self.rules_table.setShowGrid(False)
        
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        add_button = QPushButton("➕ 添加规则")
        add_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #48bb78, stop:1 #38a169);")
        add_button.clicked.connect(self._on_add_rule)
        
        edit_button = QPushButton("✏️ 编辑规则")
        edit_button.clicked.connect(self._on_edit_rule)
        
        delete_button = QPushButton("🗑️ 删除规则")
        delete_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #fc8181, stop:1 #f56565);")
        delete_button.clicked.connect(self._on_delete_rule)
        
        import_button = QPushButton("📥 导入规则")
        import_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #9f7aea, stop:1 #805ad5);")
        import_button.clicked.connect(self._on_import_rules)
        
        export_button = QPushButton("📤 导出规则")
        export_button.clicked.connect(self._on_export_rules)
        
        button_layout.addWidget(add_button)
        button_layout.addWidget(edit_button)
        button_layout.addWidget(delete_button)
        button_layout.addWidget(import_button)
        button_layout.addWidget(export_button)
        button_layout.addStretch()
        
        layout.addWidget(self.rules_table)
        layout.addLayout(button_layout)
        
        self._populate_rules_table()
        
        return widget
    
    def _create_headers_tab(self):
        """创建请求头标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(12)
        layout.setContentsMargins(10, 15, 10, 10)
        
        self.headers_table = QTableWidget()
        self.headers_table.setColumnCount(3)
        self.headers_table.setHorizontalHeaderLabels([
            "启用", "请求头名称", "请求头值"
        ])
        
        self.headers_table.setColumnWidth(0, 60)
        self.headers_table.setColumnWidth(1, 180)
        self.headers_table.setColumnWidth(2, 480)
        
        self.headers_table.setAlternatingRowColors(True)
        self.headers_table.verticalHeader().setVisible(False)
        self.headers_table.setShowGrid(False)
        
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        add_button = QPushButton("➕ 添加请求头")
        add_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #48bb78, stop:1 #38a169);")
        add_button.clicked.connect(self._on_add_header)
        
        edit_button = QPushButton("✏️ 编辑请求头")
        edit_button.clicked.connect(self._on_edit_header)
        
        delete_button = QPushButton("🗑️ 删除请求头")
        delete_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #fc8181, stop:1 #f56565);")
        delete_button.clicked.connect(self._on_delete_header)
        
        button_layout.addWidget(add_button)
        button_layout.addWidget(edit_button)
        button_layout.addWidget(delete_button)
        button_layout.addStretch()
        
        quick_layout = QHBoxLayout()
        quick_layout.setSpacing(10)
        
        quick_label = QLabel("快捷添加:")
        quick_label.setStyleSheet("font-weight: bold; color: #4a5568;")
        
        cookie_button = QPushButton("🍪 Cookie")
        cookie_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #ecc94b, stop:1 #d69e2e);")
        cookie_button.clicked.connect(lambda: self._add_quick_header("Cookie", "sessionid=12345"))
        
        auth_button = QPushButton("🔑 认证头")
        auth_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #ed8936, stop:1 #dd6b20);")
        auth_button.clicked.connect(lambda: self._add_quick_header("Authorization", "Bearer token"))
        
        user_agent_button = QPushButton("🌐 User-Agent")
        user_agent_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #38b2ac, stop:1 #319795);")
        user_agent_button.clicked.connect(lambda: self._add_quick_header("User-Agent", "APISentinel_Bluechips"))
        
        quick_layout.addWidget(quick_label)
        quick_layout.addWidget(cookie_button)
        quick_layout.addWidget(auth_button)
        quick_layout.addWidget(user_agent_button)
        quick_layout.addStretch()
        
        layout.addWidget(self.headers_table)
        layout.addLayout(button_layout)
        layout.addLayout(quick_layout)
        
        self._populate_headers_table()
        
        return widget
    
    def _create_fuzzing_tab(self):
        """创建变异测试标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(12)
        layout.setContentsMargins(10, 15, 10, 10)
        
        category_layout = QHBoxLayout()
        category_layout.setSpacing(12)
        
        category_label = QLabel("分类:")
        category_label.setStyleSheet("font-weight: bold; color: #4a5568;")
        
        self.category_combo = QComboBox()
        self.category_combo.addItems(["💉 SQL注入", "⚠️ XSS攻击", "📁 路径遍历", "⚙️ 命令注入", "🔧 自定义"])
        self.category_combo.currentTextChanged.connect(self._on_category_change)
        
        category_layout.addWidget(category_label)
        category_layout.addWidget(self.category_combo)
        category_layout.addStretch()
        
        self.payload_list = QListWidget()
        self.payload_list.setAlternatingRowColors(True)
        
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        add_button = QPushButton("➕ 添加 Payload")
        add_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #48bb78, stop:1 #38a169);")
        add_button.clicked.connect(self._on_add_payload)
        
        delete_button = QPushButton("🗑️ 删除 Payload")
        delete_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #fc8181, stop:1 #f56565);")
        delete_button.clicked.connect(self._on_delete_payload)
        
        import_button = QPushButton("📥 导入 Payload")
        import_button.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #9f7aea, stop:1 #805ad5);")
        import_button.clicked.connect(self._on_import_payloads)
        
        export_button = QPushButton("📤 导出 Payload")
        export_button.clicked.connect(self._on_export_payloads)
        
        button_layout.addWidget(add_button)
        button_layout.addWidget(delete_button)
        button_layout.addWidget(import_button)
        button_layout.addWidget(export_button)
        button_layout.addStretch()
        
        layout.addLayout(category_layout)
        layout.addWidget(self.payload_list)
        layout.addLayout(button_layout)
        
        self._populate_payload_list()
        
        return widget
    
    def _create_safety_tab(self):
        """创建安全设置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        layout.setContentsMargins(10, 15, 10, 10)
        
        safe_mode_group = ModernGroupBox("🔒 安全模式")
        safe_mode_layout = QVBoxLayout()
        safe_mode_layout.setSpacing(10)
        
        self.safe_mode_checkbox = QCheckBox("启用安全模式（默认开启）")
        self.safe_mode_checkbox.setChecked(self.settings.get("safe_mode", True))
        self.safe_mode_checkbox.setStyleSheet("""
            QCheckBox {
                font-size: 14px;
                font-weight: bold;
                spacing: 10px;
            }
            QCheckBox::indicator {
                width: 24px;
                height: 24px;
                border-radius: 6px;
                border: 2px solid #475569;
                background-color: #1e293b;
            }
            QCheckBox::indicator:checked {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0ea5e9, stop:1 #06b6d4);
                border-color: #0ea5e9;
                image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjMiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBvbHlsaW5lIHBvaW50cz0iMjAgNiA5IDE3IDQgMTIiPjwvcG9seWxpbmU+PC9zdmc+);
            }
            QCheckBox::indicator:hover {
                border-color: #0ea5e9;
            }
        """)
        
        safe_mode_layout.addWidget(self.safe_mode_checkbox)
        safe_mode_group.setLayout(safe_mode_layout)
        
        methods_group = ModernGroupBox("🚫 拦截方法")
        methods_layout = QHBoxLayout()
        methods_layout.setSpacing(20)
        
        self.method_checkboxes = {}
        methods = ["DELETE", "PUT", "PATCH"]
        blocked_methods = self.settings.get("blocked_methods", ["DELETE", "PUT"])
        
        for method in methods:
            checkbox = QCheckBox(f"⛔ {method}")
            checkbox.setChecked(method in blocked_methods)
            checkbox.setStyleSheet("""
                QCheckBox {
                    font-size: 13px;
                    font-weight: bold;
                    spacing: 8px;
                    color: #e2e8f0;
                }
                QCheckBox::indicator {
                    width: 20px;
                    height: 20px;
                    border-radius: 5px;
                    border: 2px solid #475569;
                    background-color: #1e293b;
                }
                QCheckBox::indicator:checked {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #0ea5e9, stop:1 #06b6d4);
                    border-color: #0ea5e9;
                    image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjMiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBvbHlsaW5lIHBvaW50cz0iMjAgNiA5IDE3IDQgMTIiPjwvcG9seWxpbmU+PC9zdmc+);
                }
                QCheckBox::indicator:hover {
                    border-color: #0ea5e9;
                }
            """)
            self.method_checkboxes[method] = checkbox
            methods_layout.addWidget(checkbox)
        
        methods_layout.addStretch()
        methods_group.setLayout(methods_layout)
        
        keywords_group = ModernGroupBox("⚠️ 危险关键词")
        keywords_layout = QVBoxLayout()
        
        self.keywords_text = QTextEdit()
        self.keywords_text.setPlaceholderText("每行一个关键词...")
        self.keywords_text.setMaximumHeight(120)
        self.keywords_text.setText("\n".join(self.settings.get("dangerous_keywords", [
            "delete", "remove", "drop", "truncate", "destroy", "clear", "purge"
        ])))
        
        keywords_layout.addWidget(self.keywords_text)
        keywords_group.setLayout(keywords_layout)
        
        blacklist_group = ModernGroupBox("📋 URL 黑名单")
        blacklist_layout = QVBoxLayout()
        
        self.blacklist_text = QTextEdit()
        self.blacklist_text.setPlaceholderText("每行一个 URL 模式（支持正则表达式）...")
        self.blacklist_text.setMaximumHeight(120)
        self.blacklist_text.setText("\n".join(self.settings.get("blacklist", [])))
        
        blacklist_layout.addWidget(self.blacklist_text)
        blacklist_group.setLayout(blacklist_layout)
        
        layout.addWidget(safe_mode_group)
        layout.addWidget(methods_group)
        
        detector_group = ModernGroupBox("🔍 安全检测器")
        detector_layout = QVBoxLayout()
        detector_layout.setSpacing(12)
        
        detector_cb_style = """
            QCheckBox {
                font-size: 13px;
                font-weight: bold;
                spacing: 10px;
                color: #e2e8f0;
            }
            QCheckBox::indicator {
                width: 22px;
                height: 22px;
                border-radius: 6px;
                border: 2px solid #475569;
                background-color: #1e293b;
            }
            QCheckBox::indicator:checked {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0ea5e9, stop:1 #06b6d4);
                border-color: #0ea5e9;
                image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjMiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBvbHlsaW5lIHBvaW50cz0iMjAgNiA5IDE3IDQgMTIiPjwvcG9seWxpbmU+PC9zdmc+);
            }
            QCheckBox::indicator:hover {
                border-color: #0ea5e9;
            }
        """
        
        self.sensitive_detection_cb = QCheckBox("🔐 敏感信息检测（默认启用）")
        self.sensitive_detection_cb.setChecked(self.settings.get("enable_sensitive_detection", True))
        self.sensitive_detection_cb.setStyleSheet(detector_cb_style)
        
        self.jwt_detection_cb = QCheckBox("🎫 JWT 安全检测（默认启用）")
        self.jwt_detection_cb.setChecked(self.settings.get("enable_jwt_detection", True))
        self.jwt_detection_cb.setStyleSheet(detector_cb_style)
        
        self.idor_detection_cb = QCheckBox("🎭 IDOR 漏洞检测")
        self.idor_detection_cb.setChecked(self.settings.get("enable_idor_detection", False))
        self.idor_detection_cb.setStyleSheet(detector_cb_style)
        
        self.auth_bypass_detection_cb = QCheckBox("🔓 认证绕过检测")
        self.auth_bypass_detection_cb.setChecked(self.settings.get("enable_auth_bypass_detection", False))
        self.auth_bypass_detection_cb.setStyleSheet(detector_cb_style)
        
        self.upload_detection_cb = QCheckBox("📤 上传漏洞检测")
        self.upload_detection_cb.setChecked(self.settings.get("enable_upload_detection", False))
        self.upload_detection_cb.setStyleSheet(detector_cb_style)
        
        detector_layout.addWidget(self.sensitive_detection_cb)
        detector_layout.addWidget(self.jwt_detection_cb)
        detector_layout.addWidget(self.idor_detection_cb)
        detector_layout.addWidget(self.auth_bypass_detection_cb)
        detector_layout.addWidget(self.upload_detection_cb)
        detector_group.setLayout(detector_layout)
        
        layout.addWidget(detector_group)
        layout.addWidget(keywords_group)
        layout.addWidget(blacklist_group)
        
        return widget
    
    def _create_disclaimer_tab(self):
        """创建免责声明标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        layout.setContentsMargins(10, 15, 10, 10)
        
        disclaimer_group = ModernGroupBox("📜 免责声明")
        disclaimer_layout = QVBoxLayout()
        disclaimer_layout.setSpacing(15)
        
        disclaimer_text = QTextEdit()
        disclaimer_text.setReadOnly(True)
        disclaimer_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e293b;
                border: 2px solid #334155;
                border-radius: 8px;
                padding: 15px;
                font-size: 13px;
                line-height: 1.6;
                color: #e2e8f0;
            }
        """)
        
        disclaimer_content = """
<h2 style="color: #e2e8f0; text-align: center; margin-bottom: 20px;">
    ⚠️ 重要声明 - 请仔细阅读
</h2>

<h3 style="color: #e53e3e; margin-top: 15px;">🔴 法律声明</h3>
<p style="margin-left: 10px;">
    本工具（APISentinel_Bluechips）仅供安全研究和授权测试使用。使用本工具进行任何未经授权的测试活动均属违法行为。
</p>

<h3 style="color: #dd6b20; margin-top: 15px;">🟠 使用限制</h3>
<ul style="margin-left: 20px;">
    <li><strong>仅限授权使用：</strong>在使用本工具前，必须获得目标系统所有者的明确书面授权</li>
    <li><strong>禁止非法用途：</strong>严禁用于任何非法、恶意或未经授权的测试活动</li>
    <li><strong>责任自负：</strong>用户需自行承担使用本工具所产生的一切法律责任</li>
    <li><strong>遵守法律：</strong>使用本工具时必须遵守所在国家和地区的相关法律法规</li>
</ul>

<h3 style="color: #d69e2e; margin-top: 15px;">🟡 免责条款</h3>
<ul style="margin-left: 20px;">
    <li>本工具按"现状"提供，不提供任何明示或暗示的保证</li>
    <li>开发者不对因使用本工具而导致的任何直接或间接损失承担责任</li>
    <li>本工具可能存在缺陷或错误，用户需自行评估风险</li>
    <li>开发者不对用户的任何违法行为承担责任</li>
</ul>

<h3 style="color: #38a169; margin-top: 15px;">🟢 合法使用建议</h3>
<ul style="margin-left: 20px;">
    <li><strong>获取授权：</strong>在进行任何测试前，确保已获得书面授权</li>
    <li><strong>限定范围：</strong>明确测试范围，不要超出授权范围进行测试</li>
    <li><strong>保护数据：</strong>测试过程中获取的数据应妥善保管，不得泄露</li>
    <li><strong>遵守协议：</strong>遵守保密协议和职业道德准则</li>
    <li><strong>及时报告：</strong>发现漏洞后应及时向相关方报告</li>
</ul>

<h3 style="color: #3182ce; margin-top: 15px;">🔵 安全模式</h3>
<p style="margin-left: 10px;">
    本工具内置安全模式功能，默认启用。安全模式会拦截危险的 HTTP 方法（如 DELETE、PUT、PATCH），
    防止在测试过程中意外删除或修改数据。建议在生产环境中始终保持安全模式启用状态。
</p>

<h3 style="color: #805ad5; margin-top: 15px;">🟣 风险提示</h3>
<ul style="margin-left: 20px;">
    <li>测试可能对目标系统造成影响，请谨慎操作</li>
    <li>某些测试可能触发安全警报或日志记录</li>
    <li>测试可能导致服务中断或数据丢失</li>
    <li>请确保已做好充分的备份和恢复准备</li>
</ul>

<h3 style="color: #2d3748; margin-top: 15px;">⚫ 知识产权</h3>
<p style="margin-left: 10px;">
    本工具由 bluechips 开发，受知识产权法保护。未经许可，不得用于商业目的或进行二次分发。
</p>

<h3 style="color: #2d3748; margin-top: 15px;">📧 联系方式</h3>
<p style="margin-left: 10px;">
    如有疑问或建议，请联系：<strong>bluechipszhao@163.com</strong>
</p>

<div style="background-color: #7f1d1d; padding: 15px; border-radius: 8px; margin-top: 20px; border-left: 4px solid #ef4444;">
    <p style="margin: 0; color: #fca5a5; font-weight: bold; text-align: center;">
        ⚠️ 使用本工具即表示您已阅读、理解并同意遵守以上声明。<br>
        如不同意，请立即停止使用本工具。
    </p>
</div>
"""
        
        disclaimer_text.setHtml(disclaimer_content)
        
        disclaimer_layout.addWidget(disclaimer_text)
        
        agree_layout = QHBoxLayout()
        agree_layout.addStretch()
        
        self.agree_checkbox = QCheckBox("我已阅读并同意以上免责声明")
        self.agree_checkbox.setChecked(self.settings.get("agreed_disclaimer", False))
        self.agree_checkbox.setStyleSheet("""
            QCheckBox {
                font-size: 14px;
                font-weight: bold;
                spacing: 10px;
                color: #e2e8f0;
            }
            QCheckBox::indicator {
                width: 24px;
                height: 24px;
                border-radius: 6px;
                border: 2px solid #475569;
                background-color: #1e293b;
            }
            QCheckBox::indicator:checked {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0ea5e9, stop:1 #06b6d4);
                border-color: #0ea5e9;
                image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjMiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBvbHlsaW5lIHBvaW50cz0iMjAgNiA5IDE3IDQgMTIiPjwvcG9seWxpbmU+PC9zdmc+);
            }
            QCheckBox::indicator:hover {
                border-color: #0ea5e9;
            }
        """)
        
        agree_layout.addWidget(self.agree_checkbox)
        agree_layout.addStretch()
        
        disclaimer_layout.addLayout(agree_layout)
        disclaimer_group.setLayout(disclaimer_layout)
        
        layout.addWidget(disclaimer_group)
        
        return widget
    
    def _populate_rules_table(self):
        """填充规则表格"""
        self.rules_table.setRowCount(0)
        
        rules = sensitive_rule_library.get_rules()
        for i, rule in enumerate(rules):
            row_position = self.rules_table.rowCount()
            self.rules_table.insertRow(row_position)
            
            checkbox = QCheckBox()
            checkbox.setChecked(rule.get("enabled", True))
            self.rules_table.setCellWidget(row_position, 0, checkbox)
            
            self.rules_table.setItem(row_position, 1, QTableWidgetItem(rule["name"]))
            self.rules_table.setItem(row_position, 2, QTableWidgetItem(rule["pattern"]))
            
            level_item = QTableWidgetItem(rule["level"])
            level_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if rule["level"] == "High":
                level_item.setBackground(QColor(245, 101, 101))
                level_item.setForeground(QColor(255, 255, 255))
            elif rule["level"] == "Medium":
                level_item.setBackground(QColor(236, 201, 75))
                level_item.setForeground(QColor(45, 55, 72))
            else:
                level_item.setBackground(QColor(66, 153, 225))
                level_item.setForeground(QColor(255, 255, 255))
            
            self.rules_table.setItem(row_position, 3, level_item)
            self.rules_table.setItem(row_position, 4, QTableWidgetItem(rule.get("category", "general")))
    
    def _populate_headers_table(self):
        """填充请求头表格"""
        self.headers_table.setRowCount(0)
        
        headers = self.settings.get("custom_headers", {})
        for name, value in headers.items():
            row_position = self.headers_table.rowCount()
            self.headers_table.insertRow(row_position)
            
            checkbox = QCheckBox()
            checkbox.setChecked(True)
            self.headers_table.setCellWidget(row_position, 0, checkbox)
            
            self.headers_table.setItem(row_position, 1, QTableWidgetItem(name))
            self.headers_table.setItem(row_position, 2, QTableWidgetItem(value))
    
    def _populate_payload_list(self):
        """填充 Payload 列表"""
        self.payload_list.clear()
        
        category_map = {
            "💉 SQL注入": "sqli",
            "⚠️ XSS攻击": "xss",
            "📁 路径遍历": "path_traversal",
            "⚙️ 命令注入": "command_injection",
            "🔧 自定义": "custom"
        }
        
        category = category_map.get(self.category_combo.currentText(), "sqli")
        payloads = self.fuzzer.get_payloads(category)
        
        for payload in payloads:
            item = QListWidgetItem(f"• {payload}")
            self.payload_list.addItem(item)
    
    def _on_add_rule(self):
        """处理添加规则按钮点击"""
        name, ok = QInputDialog.getText(self, "➕ 添加规则", "规则名称:")
        if ok and name:
            pattern, ok = QInputDialog.getText(self, "➕ 添加规则", "正则表达式:")
            if ok and pattern:
                level, ok = QInputDialog.getItem(self, "➕ 添加规则", "风险等级:", ["High", "Medium", "Low"])
                if ok:
                    category, ok = QInputDialog.getText(self, "➕ 添加规则", "分类:")
                    if ok:
                        sensitive_rule_library.add_rule(name, pattern, level, category=category)
                        self._populate_rules_table()
    
    def _on_edit_rule(self):
        """处理编辑规则按钮点击"""
        current_row = self.rules_table.currentRow()
        if current_row >= 0:
            name = self.rules_table.item(current_row, 1).text()
            pattern = self.rules_table.item(current_row, 2).text()
            level = self.rules_table.item(current_row, 3).text()
            category = self.rules_table.item(current_row, 4).text()
            
            new_name, ok = QInputDialog.getText(self, "✏️ 编辑规则", "规则名称:", text=name)
            if ok:
                new_pattern, ok = QInputDialog.getText(self, "✏️ 编辑规则", "正则表达式:", text=pattern)
                if ok:
                    new_level, ok = QInputDialog.getItem(self, "✏️ 编辑规则", "风险等级:", ["High", "Medium", "Low"], current=0 if level == "High" else 1 if level == "Medium" else 2)
                    if ok:
                        new_category, ok = QInputDialog.getText(self, "✏️ 编辑规则", "分类:", text=category)
                        if ok:
                            sensitive_rule_library.remove_rule(name)
                            sensitive_rule_library.add_rule(new_name, new_pattern, new_level, category=new_category)
                            self._populate_rules_table()
    
    def _on_delete_rule(self):
        """处理删除规则按钮点击"""
        current_row = self.rules_table.currentRow()
        if current_row >= 0:
            name = self.rules_table.item(current_row, 1).text()
            if QMessageBox.question(self, "🗑️ 删除规则", f"确定要删除规则 '{name}' 吗?") == QMessageBox.StandardButton.Yes:
                sensitive_rule_library.remove_rule(name)
                self._populate_rules_table()
    
    def _on_import_rules(self):
        """处理导入规则按钮点击"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self, "📥 导入规则", "", "JSON 文件;;所有文件"
        )
        if file_path:
            try:
                sensitive_rule_library.load_rules_from_file(file_path)
                self._populate_rules_table()
                QMessageBox.information(self, "✅ 成功", "规则导入成功")
            except Exception as e:
                QMessageBox.critical(self, "❌ 错误", f"导入失败: {str(e)}")
    
    def _on_export_rules(self):
        """处理导出规则按钮点击"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(
            self, "📤 导出规则", f"{APP_NAME}_rules.json", "JSON 文件 (*.json)"
        )
        if file_path:
            try:
                sensitive_rule_library.save_rules_to_file(file_path)
                QMessageBox.information(self, "✅ 成功", "规则导出成功")
            except Exception as e:
                QMessageBox.critical(self, "❌ 错误", f"导出失败: {str(e)}")
    
    def _on_add_header(self):
        """处理添加请求头按钮点击"""
        name, ok = QInputDialog.getText(self, "➕ 添加请求头", "请求头名称:")
        if ok and name:
            value, ok = QInputDialog.getText(self, "➕ 添加请求头", "请求头值:")
            if ok:
                headers = self.settings.get("custom_headers", {})
                headers[name] = value
                self.settings["custom_headers"] = headers
                self._populate_headers_table()
    
    def _on_edit_header(self):
        """处理编辑请求头按钮点击"""
        current_row = self.headers_table.currentRow()
        if current_row >= 0:
            old_name = self.headers_table.item(current_row, 1).text()
            old_value = self.headers_table.item(current_row, 2).text()
            
            new_name, ok = QInputDialog.getText(self, "✏️ 编辑请求头", "请求头名称:", text=old_name)
            if ok:
                new_value, ok = QInputDialog.getText(self, "✏️ 编辑请求头", "请求头值:", text=old_value)
                if ok:
                    headers = self.settings.get("custom_headers", {})
                    if old_name in headers:
                        del headers[old_name]
                    headers[new_name] = new_value
                    self.settings["custom_headers"] = headers
                    self._populate_headers_table()
    
    def _on_delete_header(self):
        """处理删除请求头按钮点击"""
        current_row = self.headers_table.currentRow()
        if current_row >= 0:
            name = self.headers_table.item(current_row, 1).text()
            if QMessageBox.question(self, "🗑️ 删除请求头", f"确定要删除请求头 '{name}' 吗?") == QMessageBox.StandardButton.Yes:
                headers = self.settings.get("custom_headers", {})
                if name in headers:
                    del headers[name]
                    self.settings["custom_headers"] = headers
                self._populate_headers_table()
    
    def _add_quick_header(self, name, value):
        """添加快捷请求头"""
        headers = self.settings.get("custom_headers", {})
        headers[name] = value
        self.settings["custom_headers"] = headers
        self._populate_headers_table()
    
    def _on_category_change(self):
        """处理分类变化"""
        self._populate_payload_list()
    
    def _on_add_payload(self):
        """处理添加 Payload 按钮点击"""
        payload, ok = QInputDialog.getText(self, "➕ 添加 Payload", "Payload:")
        if ok and payload:
            category_map = {
                "💉 SQL注入": "sqli",
                "⚠️ XSS攻击": "xss",
                "📁 路径遍历": "path_traversal",
                "⚙️ 命令注入": "command_injection",
                "🔧 自定义": "custom"
            }
            category = category_map.get(self.category_combo.currentText(), "sqli")
            self.fuzzer.add_payload(category, payload)
            self._populate_payload_list()
    
    def _on_delete_payload(self):
        """处理删除 Payload 按钮点击"""
        current_item = self.payload_list.currentItem()
        if current_item:
            payload = current_item.text()[2:]
            if QMessageBox.question(self, "🗑️ 删除 Payload", "确定要删除此 Payload 吗?") == QMessageBox.StandardButton.Yes:
                category_map = {
                    "💉 SQL注入": "sqli",
                    "⚠️ XSS攻击": "xss",
                    "📁 路径遍历": "path_traversal",
                    "⚙️ 命令注入": "command_injection",
                    "🔧 自定义": "custom"
                }
                category = category_map.get(self.category_combo.currentText(), "sqli")
                self.fuzzer.remove_payload(category, payload)
                self._populate_payload_list()
    
    def _on_import_payloads(self):
        """处理导入 Payload 按钮点击"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(
            self, "📥 导入 Payload", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip()]
                category_map = {
                    "💉 SQL注入": "sqli",
                    "⚠️ XSS攻击": "xss",
                    "📁 路径遍历": "path_traversal",
                    "⚙️ 命令注入": "command_injection",
                    "🔧 自定义": "custom"
                }
                category = category_map.get(self.category_combo.currentText(), "sqli")
                self.fuzzer.add_payloads(category, payloads)
                self._populate_payload_list()
                QMessageBox.information(self, "✅ 成功", f"已导入 {len(payloads)} 个 Payload")
            except Exception as e:
                QMessageBox.critical(self, "❌ 错误", f"导入失败: {str(e)}")
    
    def _on_export_payloads(self):
        """处理导出 Payload 按钮点击"""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(
            self, "📤 导出 Payload", f"{APP_NAME}_payloads.txt", "文本文件 (*.txt)"
        )
        if file_path:
            try:
                category_map = {
                    "💉 SQL注入": "sqli",
                    "⚠️ XSS攻击": "xss",
                    "📁 路径遍历": "path_traversal",
                    "⚙️ 命令注入": "command_injection",
                    "🔧 自定义": "custom"
                }
                category = category_map.get(self.category_combo.currentText(), "sqli")
                payloads = self.fuzzer.get_payloads(category)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(payloads))
                QMessageBox.information(self, "✅ 成功", f"已导出 {len(payloads)} 个 Payload")
            except Exception as e:
                QMessageBox.critical(self, "❌ 错误", f"导出失败: {str(e)}")
    
    def _load_settings(self):
        """加载设置"""
        default_settings = {
            "safe_mode": True,
            "blocked_methods": ["DELETE", "PUT"],
            "dangerous_keywords": ["delete", "remove", "drop", "truncate", "destroy", "clear", "purge"],
            "blacklist": [],
            "custom_headers": {}
        }
        
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return default_settings
        return default_settings
    
    def _save_settings(self):
        """保存设置"""
        self.settings["safe_mode"] = self.safe_mode_checkbox.isChecked()
        
        blocked_methods = []
        for method, checkbox in self.method_checkboxes.items():
            if checkbox.isChecked():
                blocked_methods.append(method)
        self.settings["blocked_methods"] = blocked_methods
        
        if hasattr(self, 'sensitive_detection_cb'):
            self.settings["enable_sensitive_detection"] = self.sensitive_detection_cb.isChecked()
            self.settings["enable_jwt_detection"] = self.jwt_detection_cb.isChecked()
            self.settings["enable_idor_detection"] = self.idor_detection_cb.isChecked()
            self.settings["enable_auth_bypass_detection"] = self.auth_bypass_detection_cb.isChecked()
            self.settings["enable_upload_detection"] = self.upload_detection_cb.isChecked()
        
        keywords = [line.strip() for line in self.keywords_text.toPlainText().split('\n') if line.strip()]
        self.settings["dangerous_keywords"] = keywords
        
        blacklist = [line.strip() for line in self.blacklist_text.toPlainText().split('\n') if line.strip()]
        self.settings["blacklist"] = blacklist
        
        if hasattr(self, 'agree_checkbox'):
            self.settings["agreed_disclaimer"] = self.agree_checkbox.isChecked()
        
        os.makedirs(os.path.dirname(self.settings_file), exist_ok=True)
        with open(self.settings_file, 'w', encoding='utf-8') as f:
            json.dump(self.settings, f, indent=2, ensure_ascii=False)
    
    def _on_save(self):
        """处理保存按钮点击"""
        self._save_settings()
        QMessageBox.information(self, "✅ 成功", "设置已保存")
        self.accept()
    
    def _on_apply(self):
        """处理应用按钮点击"""
        self._save_settings()
        QMessageBox.information(self, "✅ 成功", "设置已应用")
    
    def _on_reset(self):
        """处理重置按钮点击"""
        if QMessageBox.question(self, "🔄 重置设置", "确定要重置所有设置吗?") == QMessageBox.StandardButton.Yes:
            self.settings = {
                "safe_mode": True,
                "blocked_methods": ["DELETE", "PUT"],
                "dangerous_keywords": ["delete", "remove", "drop", "truncate", "destroy", "clear", "purge"],
                "blacklist": [],
                "custom_headers": {},
                "enable_sensitive_detection": True,
                "enable_jwt_detection": True,
                "enable_idor_detection": False,
                "enable_auth_bypass_detection": False,
                "enable_upload_detection": False
            }
            self._populate_rules_table()
            self._populate_headers_table()
            self._populate_payload_list()
            
            self.safe_mode_checkbox.setChecked(True)
            for method, checkbox in self.method_checkboxes.items():
                checkbox.setChecked(method in ["DELETE", "PUT"])
            
            if hasattr(self, 'sensitive_detection_cb'):
                self.sensitive_detection_cb.setChecked(True)
                self.jwt_detection_cb.setChecked(True)
                self.idor_detection_cb.setChecked(False)
                self.auth_bypass_detection_cb.setChecked(False)
                self.upload_detection_cb.setChecked(False)
            
            self.keywords_text.setText("\n".join(["delete", "remove", "drop", "truncate", "destroy", "clear", "purge"]))
            self.blacklist_text.clear()
