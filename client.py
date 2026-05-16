import sys
import requests
import time
import networkx as nx
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLineEdit, QPushButton, QTextEdit, QLabel, QTabWidget, QListWidget, QListWidgetItem, QMessageBox)
from PyQt6.QtCore import QThread, pyqtSignal, Qt

API_BASE_URL = "http://127.0.0.1:8000/api/v1"

class GraphCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        self.fig.patch.set_facecolor('#1e1e1e')
        self.axes = self.fig.add_subplot(111)
        self.axes.set_facecolor('#1e1e1e')
        super().__init__(self.fig)

    def plot_graph(self, graph_data):
        self.axes.clear()
        self.axes.axis('off')
        
        G = nx.Graph()
        
        for node in graph_data.get("nodes", []):
            G.add_node(node["id"], type=node["type"])
        for edge in graph_data.get("edges", []):
            G.add_edge(edge["source"], edge["target"])
            
        if not G.nodes:
            self.axes.text(0.5, 0.5, 'Граф порожній\n(Активи не знайдені або недоступні)', 
                           color='#00ff00', ha='center', va='center', fontsize=14)
            self.draw()
            return

        color_map = []
        sizes =[]
        labels = {}
        for node, attr in G.nodes(data=True):
            labels[node] = str(node)
            if attr.get('type') == 'Vulnerability':
                color_map.append('#ff4444') # Червоний
                sizes.append(1200)
            else:
                color_map.append('#00ff00') # Зелений
                sizes.append(2500)
                
        # Використовуємо більш надійний алгоритм розкладки
        pos = nx.spring_layout(G, seed=42)
        nx.draw_networkx_nodes(G, pos, ax=self.axes, node_color=color_map, node_size=sizes, edgecolors='white', linewidths=2)
        nx.draw_networkx_edges(G, pos, ax=self.axes, edge_color='#888888', width=2)
        nx.draw_networkx_labels(G, pos, labels, ax=self.axes, font_color='white', font_size=10, font_weight='bold')
        self.axes.margins(0.20)  # Додаємо 20% відступів по краях (щоб не обрізало)
        self.fig.tight_layout()  
        
        self.draw()

class OSINTWorker(QThread):
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str, dict)

    def __init__(self, target_domain):
        super().__init__()
        self.target_domain = target_domain

    def run(self):
        try:
            self.update_signal.emit(f"[*] Ініціалізація сканування для {self.target_domain}...")
            response = requests.post(f"{API_BASE_URL}/scan", json={"target_domain": self.target_domain})
            response.raise_for_status()
            task_id = response.json().get("task_id")
            
            self.update_signal.emit(f"[*] Завдання створено (Task ID: {task_id}).\n[*] Очікуємо завершення...")
            
            while True:
                time.sleep(5)
                res = requests.get(f"{API_BASE_URL}/report/{task_id}")
                
                if res.status_code == 200:
                    data = res.json()
                    status = data.get("status")
                    
                    if status == "completed":
                        self.update_signal.emit("\n[+] Сканування успішно завершено!")
                        final_text = format_report_text(self.target_domain, data.get("assessments",[]))
                        self.finished_signal.emit(final_text, data.get("graph_data", {}))
                        break
                    elif status in ["failed", "error"]:
                        self.finished_signal.emit("\n[!] Сталася помилка на сервері.", {})
                        break
                    else:
                        self.update_signal.emit(f"[*] Статус: {status}. Аналіз триває...")
                elif res.status_code == 404:
                    self.update_signal.emit("[*] Очікування запису в базу даних...")
                    
        except Exception as e:
            self.finished_signal.emit(f"\n[!] Помилка: {e}", {})

def format_report_text(domain, assessments):
    """Допоміжна функція для красивого форматування тексту"""
    text = f"\n{'='*50}\nФІНАЛЬНИЙ ЗВІТ OSINT ПО ДОМЕНУ: {domain}\n{'='*50}\n\n"
    
    if not assessments:
        text += "Вразливостей не знайдено або активи недоступні.\n"
        return text

    # 1. Виводимо компактну математичну оцінку для кожного активу
    text += "МАТЕМАТИЧНА ОЦІНКА АКТИВІВ (CRQ):\n"
    for idx, asm in enumerate(assessments, 1):
        score = asm.get('risk_score', 0)
        category = asm.get('risk_category', 'Невідомо')
        text += f"[Актив #{idx}] Оцінка: {score:.2f} балів | Статус: {category}\n"
    
    # 2. Виводимо глобальний звіт ШІ лише ОДИН раз
    text += "\n" + "="*50 + "\n"
    text += "ГЛОБАЛЬНИЙ АНАЛІЗ ШІ (Gemini):\n"
    text += "-"*50 + "\n"
    
    # Беремо звіт з першого активу, оскільки він оцінює весь граф цілком
    llm_report = assessments[0].get('llm_report', 'Звіт відсутній')
    text += f"{llm_report}\n"
    text += "="*50 + "\n"
    
    return text

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OSINT Threat Analyzer (AI Powered)")
        self.resize(1000, 700)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # Панель вводу
        self.input_layout = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Введіть домен або IP (наприклад, 45.33.32.156)")
        self.scan_btn = QPushButton("Запустити OSINT")
        self.input_layout.addWidget(self.domain_input)
        self.input_layout.addWidget(self.scan_btn)
        self.layout.addLayout(self.input_layout)

        # Система вкладок
        self.tabs = QTabWidget()
        self.terminal_tab = QWidget()
        self.graph_tab = QWidget()
        self.history_tab = QWidget() # НОВА ВКЛАДКА
        
        self.tabs.addTab(self.terminal_tab, "Термінал (Звіт)")
        self.tabs.addTab(self.graph_tab, "Граф знань")
        self.tabs.addTab(self.history_tab, "Історія сканувань")
        self.layout.addWidget(self.tabs)

        # 1. Вкладка Терміналу
        term_layout = QVBoxLayout(self.terminal_tab)
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: Consolas; font-size: 14px;")
        term_layout.addWidget(self.console_output)

        # 2. Вкладка Графа
        graph_layout = QVBoxLayout(self.graph_tab)
        self.graph_canvas = GraphCanvas(self)
        graph_layout.addWidget(self.graph_canvas)

        # 3. Вкладка Історії
        history_layout = QVBoxLayout(self.history_tab)
        self.refresh_hist_btn = QPushButton("Оновити історію")
        self.history_list = QListWidget()
        self.history_list.setStyleSheet("font-size: 14px; padding: 5px;")
        history_layout.addWidget(self.refresh_hist_btn)
        history_layout.addWidget(self.history_list)

        # Підключення кнопок
        self.scan_btn.clicked.connect(self.start_scan)
        self.refresh_hist_btn.clicked.connect(self.load_history)
        self.history_list.itemDoubleClicked.connect(self.fetch_historical_report)

        # Завантажуємо історію при старті
        self.load_history()

    def start_scan(self):
        domain = self.domain_input.text().strip()
        if not domain: return
        
        self.scan_btn.setEnabled(False)
        self.console_output.clear()
        self.graph_canvas.axes.clear()
        self.graph_canvas.draw()
        self.tabs.setCurrentIndex(0)
        
        self.worker = OSINTWorker(domain)
        self.worker.update_signal.connect(self.append_log)
        self.worker.finished_signal.connect(self.on_scan_finished)
        self.worker.start()

    def append_log(self, text):
        self.console_output.append(text)

    def on_scan_finished(self, text_result, graph_data):
        self.console_output.append(text_result)
        self.graph_canvas.plot_graph(graph_data)
        self.scan_btn.setEnabled(True)
        self.load_history() # Оновлюємо історію після завершення

    def load_history(self):
        """Завантажує список минулих сканувань з бекенду"""
        self.history_list.clear()
        try:
            res = requests.get(f"{API_BASE_URL}/history")
            if res.status_code == 200:
                for item in res.json().get("history", []):
                    # Форматуємо рядок для списку
                    display_text = f"[{item['started_at']}] {item['target']} (Статус: {item['status']})"
                    list_item = QListWidgetItem(display_text)
                    # Ховаємо task_id всередині елемента списку
                    list_item.setData(Qt.ItemDataRole.UserRole, item['task_id'])
                    list_item.setData(Qt.ItemDataRole.UserRole + 1, item['target'])
                    self.history_list.addItem(list_item)
        except Exception as e:
            self.history_list.addItem(f"Помилка завантаження історії: {e}")

    def fetch_historical_report(self, item):
        """Дістає звіт та граф при подвійному кліку на елемент історії"""
        task_id = item.data(Qt.ItemDataRole.UserRole)
        domain = item.data(Qt.ItemDataRole.UserRole + 1)
        if not task_id: return

        try:
            res = requests.get(f"{API_BASE_URL}/report/{task_id}")
            if res.status_code == 200:
                data = res.json()
                
                # 1. Формуємо текст і оновлюємо термінал (УСІ ДУЖКИ ЗАКРИТО!)
                self.console_output.clear()
                self.console_output.append(format_report_text(domain, data.get("assessments",[])))
                
                # 2. Відмальовуємо граф для цього старого сканування
                self.graph_canvas.plot_graph(data.get("graph_data", {}))
                
                # 3. Автоматично перемикаємо користувача на першу вкладку, щоб він побачив текст
                self.tabs.setCurrentIndex(0)
                
            else:
                self.console_output.append(f"[!] Помилка завантаження звіту. Код: {res.status_code}")
                
        except Exception as e:
            self.console_output.append(f"[!] Помилка з'єднання: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
