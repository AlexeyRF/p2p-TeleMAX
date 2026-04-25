import sys
import socket
import threading
import json
import os
import uuid
import html
import struct
import time
import base64 as b64
import subprocess
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextBrowser, QLineEdit, QPushButton, 
                             QFileDialog, QMessageBox, QLabel, QDialog, QListWidget,
                             QSplitter, QStackedWidget, QListWidgetItem, QCheckBox)
from PyQt6.QtCore import pyqtSignal, QObject, Qt, QUrl, QThread, QBuffer, QIODevice
from PyQt6.QtGui import QImage, QPixmap, QTextDocument

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# --- Константы и Настройки ---
PORT = 45555
CHUNK_SIZE = 1024 * 512  # 512 KB для чанков файлов

DARK_STYLESHEET = """
QMainWindow, QWidget { background-color: rgb(19, 19, 20); color: #cdd6f4; font-family: 'Segoe UI', Arial, sans-serif; }
QTextBrowser { background-color: rgb(19, 19, 20); border: none; padding: 10px; font-size: 14px; }
QLineEdit { background-color: rgb(30, 31, 32); border: 1px solid rgb(40, 42, 44); border-radius: 5px; padding: 8px; color: #cdd6f4; font-size: 14px; }
QPushButton { background-color: rgb(40, 42, 44); color: #cdd6f4; border: 1px solid rgb(30, 31, 32); border-radius: 5px; padding: 8px 15px; font-weight: bold; }
QPushButton:hover { background-color: rgb(60, 62, 64); }
QPushButton:disabled { background-color: rgb(28, 28, 28); color: #6c7086; }
QPushButton.danger { background-color: #f38ba8; color: #11111b; border: none; }
QPushButton.danger:hover { background-color: #eba0ac; }
QPushButton.success { background-color: #a6e3a1; color: #11111b; border: none; }
QListWidget { background-color: rgb(25, 26, 27); border: none; border-right: 1px solid rgb(40, 42, 44); outline: 0; }
QListWidget::item { padding: 15px; border-bottom: 1px solid rgb(40, 42, 44); }
QListWidget::item:selected { background-color: rgb(45, 47, 50); border-left: 3px solid #89b4fa; }
QScrollBar:vertical { background: rgb(19, 19, 20); width: 10px; }
QScrollBar::handle:vertical { background: rgb(60, 62, 64); border-radius: 5px; }
"""

# --- Утилиты ---
def format_size(size_bytes):
    for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
        if size_bytes < 1024.0: return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} ТБ"

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
            if not packet: return None
            data.extend(packet)
        except: return None
    return bytes(data)

# --- Передача файлов (Чанки) ---
class FileSender(QThread):
    progress = pyqtSignal(str, int)
    finished = pyqtSignal(str)
    
    # ИСПРАВЛЕНИЕ: Добавлен аргумент ips, чтобы поток знал, куда слать данные
    def __init__(self, file_path, chat_id, node, ips):
        super().__init__()
        self.file_path = file_path
        self.chat_id = chat_id
        self.node = node
        self.ips = ips 

    def run(self):
        file_size = os.path.getsize(self.file_path)
        filename = os.path.basename(self.file_path)
        file_id = str(uuid.uuid4())
        
        # Предпросмотр для изображений
        preview_b64 = ""
        ext = filename.lower().split('.')[-1]
        if ext in ['png', 'jpg', 'jpeg', 'bmp']:
            img = QImage(self.file_path)
            if not img.isNull():
                img = img.scaled(150, 150, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                ba = QBuffer()
                ba.open(QIODevice.OpenModeFlag.WriteOnly)
                img.save(ba, "PNG")
                preview_b64 = b64.b64encode(ba.data()).decode('utf-8')

        # Старт передачи
        # ИСПРАВЛЕНИЕ: Передаем self.ips в send_to_chat
        self.node.send_to_chat(self.chat_id, {
            "type": "file_start", "file_id": file_id, "filename": filename, 
            "size": file_size, "preview": preview_b64
        }, self.ips)

        sent = 0
        with open(self.file_path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                # ИСПРАВЛЕНИЕ: Передаем self.ips
                self.node.send_to_chat(self.chat_id, {
                    "type": "file_chunk", "file_id": file_id, "chunk": b64.b64encode(chunk).decode('utf-8')
                }, self.ips)
                sent += len(chunk)
                self.progress.emit(file_id, int((sent / file_size) * 100))

        # ИСПРАВЛЕНИЕ: Передаем self.ips
        self.node.send_to_chat(self.chat_id, {"type": "file_end", "file_id": file_id}, self.ips)
        self.finished.emit(file_id)

# --- Сетевой Узел ---
class P2PNode(QObject):
    message_received = pyqtSignal(str, str, dict) # ip, chat_id, payload
    handshake_complete = pyqtSignal(str)
    connection_error = pyqtSignal(str)

    def __init__(self, username):
        super().__init__()
        self.port = PORT
        self.username = username
        self.running = True
        self.encryption_keys = {}
        self.handshakes_sent = set() # Отслеживание отправленных ключей
        
        # Очереди для защиты от исчерпания сокетов
        self.offline_queue = {} # ip -> [payloads]
        self.outbound_queues = {} # ip -> Queue
        
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

        self.server_thread = threading.Thread(target=self.start_server, daemon=True)
        self.server_thread.start()

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        while self.port < PORT + 100:
            try:
                server.bind(('0.0.0.0', self.port))
                break
            except OSError: self.port += 1
                
        server.listen(100) # Увеличиваем лимит одновременных подключений
        while self.running:
            try:
                conn, addr = server.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr[0]), daemon=True).start()
            except: break

    def handle_client(self, conn, addr):
        conn.settimeout(10.0) # Защита от зависаний при обрыве соединения
        try:
            while self.running:
                raw_msglen = recvall(conn, 8)
                if not raw_msglen: break
                msglen = struct.unpack('>Q', raw_msglen)[0]
                
                if msglen > 15 * 1024 * 1024: break # Защита (лимит 15 МБ)
                
                data = recvall(conn, msglen)
                if not data: break

                try:
                    payload = json.loads(data.decode('utf-8'))
                    if payload.get("type") == "handshake":
                        self.process_handshake(addr, payload.get("pub_key"))
                        continue
                except: pass

                if addr in self.encryption_keys:
                    try:
                        decrypted = self.encryption_keys[addr].decrypt(data).decode('utf-8')
                        payload = json.loads(decrypted)
                        
                        chat_id = payload.get("chat_id", "default")
                        self.message_received.emit(addr, chat_id, payload)
                    except: pass
        except: pass
        finally: conn.close()

    def process_handshake(self, addr, peer_pub_key_b64):
        peer_pub_bytes = b64.b64decode(peer_pub_key_b64)
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        shared_key = self.private_key.exchange(peer_public_key)
        
        import hashlib
        derived_key = b64.urlsafe_b64encode(hashlib.sha256(shared_key).digest())
        self.encryption_keys[addr] = Fernet(derived_key)
        self.handshake_complete.emit(addr)

        # Отправляем ответный хэндшейк, если мы его еще не инициировали
        if addr not in self.handshakes_sent:
            self.send_handshake(addr)

        # Отправка ожидающих сообщений (offline)
        if addr in self.offline_queue and self.offline_queue[addr]:
            for payload in list(self.offline_queue[addr]):
                self._enqueue_send(addr, payload, queue_if_offline=False)
            self.offline_queue[addr] = []

    def send_to_chat(self, chat_id, payload, ips=None):
        payload["chat_id"] = chat_id
        payload["username"] = self.username
        if ips is None: return # Вот здесь пакет терялся, если ips не был передан
        for ip in ips:
            if ip in ("127.0.0.1", "localhost"): continue
            self._enqueue_send(ip, payload, True)

    def _enqueue_send(self, ip, payload, queue_if_offline):
        if ip not in self.outbound_queues:
            # Ограничиваем очередь 50 сообщениями, чтобы не забивать ОЗУ чанками больших файлов
            self.outbound_queues[ip] = Queue(maxsize=50)
            threading.Thread(target=self._send_worker, args=(ip,), daemon=True).start()
        
        # put() будет блокировать выполнение, если очередь полная - это создает backpressure
        self.outbound_queues[ip].put((payload, queue_if_offline))

    def _send_worker(self, ip):
        """Гарантирует последовательную отправку данных одному узлу без перегрузки сети."""
        while self.running:
            try:
                payload, queue_if_offline = self.outbound_queues[ip].get(timeout=1.0)
                self._send_single_sync(ip, payload, queue_if_offline)
                self.outbound_queues[ip].task_done()
            except Empty:
                continue
            except Exception:
                pass

    def _send_single_sync(self, ip, payload, queue_if_offline=True):
        max_retries = 3 if payload.get("type") != "handshake" else 1
        
        for attempt in range(max_retries):
            try:
                if ip not in self.encryption_keys and payload.get("type") != "handshake":
                    self.send_handshake(ip)
                    # Ожидаем ответа (создания ключа) до 5 секунд перед отправкой данных
                    for _ in range(10):
                        if ip in self.encryption_keys:
                            break
                        time.sleep(0.5)
                    
                    if ip not in self.encryption_keys:
                        raise Exception("Таймаут ожидания ключа шифрования (Handshake)")

                raw_data = json.dumps(payload).encode('utf-8')
                if payload.get("type") == "handshake":
                    data_to_send = raw_data # Хэндшейк отправляется открытым текстом
                else:
                    data_to_send = self.encryption_keys[ip].encrypt(raw_data)

                msg = struct.pack('>Q', len(data_to_send)) + data_to_send
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(5.0)
                client.connect((ip, PORT))
                client.sendall(msg)
                client.close()
                return # Успешно отправлено
            except Exception as e:
                time.sleep(0.5) # Пауза перед ретраем
        
        # Если дошли сюда — все попытки исчерпаны
        if queue_if_offline and payload.get("type") == "text":
            self.offline_queue.setdefault(ip, []).append(payload)
        if payload.get("type") == "handshake":
            self.connection_error.emit(f"Не в сети: {ip}")

    def send_handshake(self, ip):
        if ip not in self.handshakes_sent:
            self.handshakes_sent.add(ip)
        pub_b64 = b64.b64encode(self.public_key_bytes).decode('utf-8')
        payload = {"type": "handshake", "pub_key": pub_b64}
        self._enqueue_send(ip, payload, queue_if_offline=False)

# --- GUI ---
class ConnectDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Вход - Telemax")
        self.setFixedSize(300, 120)
        self.setStyleSheet(DARK_STYLESHEET)
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Ваш никнейм:"))
        self.name_input = QLineEdit()
        self.name_input.setText(f"User_{uuid.uuid4().hex[:4]}")
        layout.addWidget(self.name_input)
        
        self.connect_btn = QPushButton("Войти")
        self.connect_btn.clicked.connect(self.accept)
        layout.addWidget(self.connect_btn)

    def get_name(self):
        return self.name_input.text().strip() or "Anonymous"

class NewChatDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Новый чат")
        self.setFixedSize(350, 240)
        self.setStyleSheet(DARK_STYLESHEET)
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Название чата:"))
        self.name_input = QLineEdit()
        layout.addWidget(self.name_input)

        layout.addWidget(QLabel("IP адреса (через запятую):"))
        self.ips_input = QLineEdit()
        self.ips_input.setPlaceholderText("192.168.1.5, 10.0.0.2")
        layout.addWidget(self.ips_input)

        self.burn_check = QCheckBox("Одноразовый чат (Burn Chat)")
        layout.addWidget(self.burn_check)
        
        self.create_btn = QPushButton("Создать")
        self.create_btn.clicked.connect(self.accept)
        layout.addWidget(self.create_btn)

    def get_data(self):
        ips = [ip.strip() for ip in self.ips_input.text().split(",") if ip.strip()]
        return self.name_input.text().strip() or "Новый Чат", ips, self.burn_check.isChecked()

class ChatWidget(QWidget):
    def __init__(self, chat_id, name, ips, is_burn, main_window):
        super().__init__()
        self.chat_id = chat_id
        self.name = name
        self.ips = ips
        self.is_burn = is_burn
        self.main = main_window
        self.node = main_window.node
        self.downloads_dir = os.path.join(str(Path.home()), "Downloads", "Telemax")
        os.makedirs(self.downloads_dir, exist_ok=True)
        
        self.incoming_files = {} # file_id -> file pointer
        self.message_history = [] # Хранение истории чата
        
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0,0,0,0)

        # Заголовок
        header = QHBoxLayout()
        title_text = f"🔥 {self.name}" if self.is_burn else self.name
        self.title_lbl = QLabel(f"<b>{title_text}</b> <span style='color: gray; font-size: 12px;'>({', '.join(self.ips)})</span>")
        self.title_lbl.setStyleSheet("font-size: 18px; padding: 10px;")
        
        self.btn_call = QPushButton("[ Звонок ]")
        self.btn_call.clicked.connect(self.start_call)
        self.btn_call.setFixedWidth(120)
        
        header.addWidget(self.title_lbl)
        header.addStretch()
        header.addWidget(self.btn_call)
        layout.addLayout(header)

        # Чат
        self.chat_display = QTextBrowser()
        self.chat_display.setOpenExternalLinks(False)
        self.chat_display.anchorClicked.connect(self.handle_link)
        layout.addWidget(self.chat_display)

        # Ввод
        input_layout = QHBoxLayout()
        self.attach_btn = QPushButton("+")
        self.attach_btn.setFixedWidth(40)
        self.attach_btn.clicked.connect(self.send_file)
        
        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Сообщение...")
        self.msg_input.returnPressed.connect(self.send_text)
        
        self.send_btn = QPushButton("Отправить")
        self.send_btn.setFixedWidth(100)
        self.send_btn.clicked.connect(self.send_text)

        input_layout.addWidget(self.attach_btn)
        input_layout.addWidget(self.msg_input)
        input_layout.addWidget(self.send_btn)
        
        input_wrapper = QWidget()
        input_wrapper.setLayout(input_layout)
        input_wrapper.setStyleSheet("padding: 5px;")
        layout.addWidget(input_wrapper)

    def append_message(self, html_msg):
        """Универсальный метод добавления сообщения с сохранением в историю"""
        self.chat_display.append(html_msg)
        if not self.is_burn:
            self.message_history.append(html_msg)
            if hasattr(self, 'main') and self.main:
                self.main.save_state()

    def append_system(self, text):
        self.append_message(f"<div style='color:#89b4fa; font-size: 12px;'><i>Система: {text}</i></div>")

    def handle_link(self, url: QUrl):
        url_str = url.toString()
        if url_str.startswith("call:"):
            host_ip = url_str.split(":")[1]
            try:
                conf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "p2p_conf.pyw")
                subprocess.Popen([sys.executable, conf_path, "--user", self.main.username, "--ip", host_ip])
                self.append_system(f"Подключение к звонку пользователя {host_ip}...")
            except Exception as e:
                self.append_system(f"Ошибка запуска модуля звонков: {e}")

    def send_text(self):
        text = self.msg_input.text().strip()
        if not text: return
        
        payload = {"type": "text", "content": text}
        self.node.send_to_chat(self.chat_id, payload, self.ips)
        
        time_str = datetime.now().strftime("%H:%M")
        safe_text = html.escape(text).replace('\n', '<br>')
        msg_html = f"""
        <div align="right" style="margin-bottom: 8px;">
            <span style='color: gray; font-size: 11px;'>{time_str}</span> <span style='color: #a6e3a1; font-weight: bold;'>Вы</span><br>
            <table style="background-color: rgb(30, 31, 32); margin-top: 4px; border-radius: 5px;" cellspacing="0" cellpadding="10">
                <tr><td>{safe_text}</td></tr>
            </table>
        </div>
        """
        self.append_message(msg_html)
        self.msg_input.clear()

    def send_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выбрать файл")
        if not file_path: return

        self.attach_btn.setEnabled(False)
        filename = os.path.basename(file_path)
        
        # Генерация предпросмотра локально для отправителя
        ext = filename.lower().split('.')[-1]
        prev_html = ""
        if ext in ['png', 'jpg', 'jpeg', 'bmp', 'gif']:
            img = QImage(file_path)
            if not img.isNull():
                img = img.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                url = f"local_{uuid.uuid4().hex}"
                self.chat_display.document().addResource(QTextDocument.ResourceType.ImageResource, QUrl(url), img)
                prev_html = f'<br><br><img src="{url}">'

        time_str = datetime.now().strftime("%H:%M")
        msg_html = f"""
        <div align="right" style="margin-bottom: 8px;">
            <span style='color: gray; font-size: 11px;'>{time_str}</span> <span style='color: #a6e3a1; font-weight: bold;'>Вы</span><br>
            <table style="background-color: rgb(30, 31, 32); margin-top: 4px; border-radius: 5px;" cellspacing="0" cellpadding="10">
                <tr><td>Вы отправили файл: <b>{html.escape(filename)}</b>{prev_html}</td></tr>
            </table>
        </div>
        """
        self.append_message(msg_html)

        # ИСПРАВЛЕНИЕ: Передаем self.ips при создании FileSender
        self.sender_thread = FileSender(file_path, self.chat_id, self.node, self.ips)
        self.sender_thread.finished.connect(self.on_file_sent)
        self.sender_thread.start()

    def on_file_sent(self, file_id):
        self.attach_btn.setEnabled(True)
        self.append_system("Файл успешно загружен в сеть.")

    def handle_incoming(self, sender_ip, payload):
        mtype = payload.get("type")
        sender_name = html.escape(payload.get("username", sender_ip))
        time_str = datetime.now().strftime("%H:%M")

        if mtype == "text":
            content = html.escape(payload.get("content", "")).replace('\n', '<br>')
            msg_html = f"""
            <div align="left" style="margin-bottom: 8px;">
                <span style='color: #89b4fa; font-weight: bold;'>{sender_name}</span> <span style='color: gray; font-size: 11px;'>{time_str}</span><br>
                <table style="background-color: rgb(30, 31, 32); margin-top: 4px; border-radius: 5px;" cellspacing="0" cellpadding="10">
                    <tr><td>{content}</td></tr>
                </table>
            </div>
            """
            self.append_message(msg_html)
            
        elif mtype == "call_invite":
            msg_html = f"""
            <div align="left" style="margin-bottom: 8px;">
                <span style='color: #89b4fa; font-weight: bold;'>{sender_name}</span> <span style='color: gray; font-size: 11px;'>{time_str}</span><br>
                <table style="background-color: rgb(30, 31, 32); margin-top: 4px; border-radius: 5px;" cellspacing="0" cellpadding="10">
                    <tr><td>
                        <b>📹 Входящий звонок</b><br>
                        Пользователь начал конференцию и приглашает вас присоединиться.<br><br>
                        <a href="call:{sender_ip}" style="color: #a6e3a1; text-decoration: none; font-weight: bold;">[ Подключиться к звонку ]</a>
                    </td></tr>
                </table>
            </div>
            """
            self.append_message(msg_html)

        elif mtype == "file_start":
            fid = payload["file_id"]
            fname = os.path.basename(payload["filename"])
            preview = payload.get("preview", "")
            
            save_path = os.path.join(self.downloads_dir, fname)
            base, ext = os.path.splitext(save_path)
            counter = 1
            while os.path.exists(save_path):
                save_path = f"{base}_{counter}{ext}"
                counter += 1
                
            self.incoming_files[fid] = {"path": save_path, "file": open(save_path, "wb")}
            
            prev_html = ""
            if preview:
                try:
                    img_data = b64.b64decode(preview)
                    img = QImage.fromData(img_data)
                    url = f"img_{fid}"
                    # Регистрация ресурса для отображения base64 картинки внутри QTextBrowser
                    self.chat_display.document().addResource(QTextDocument.ResourceType.ImageResource, QUrl(url), img)
                    prev_html = f'<br><br><img src="{url}">'
                except Exception as e:
                    print(f"Ошибка загрузки превью: {e}")
            
            msg_html = f"""
            <div align="left" style="margin-bottom: 8px;">
                <span style='color: #89b4fa; font-weight: bold;'>{sender_name}</span> <span style='color: gray; font-size: 11px;'>{time_str}</span><br>
                <table style="background-color: rgb(30, 31, 32); margin-top: 4px; border-radius: 5px;" cellspacing="0" cellpadding="10">
                    <tr><td>Вам отправлен файл: <b>{html.escape(fname)}</b>{prev_html}</td></tr>
                </table>
            </div>
            """
            self.append_message(msg_html)
            
        elif mtype == "file_chunk":
            fid = payload["file_id"]
            if fid in self.incoming_files:
                self.incoming_files[fid]["file"].write(b64.b64decode(payload["chunk"]))
                
        elif mtype == "file_end":
            fid = payload["file_id"]
            if fid in self.incoming_files:
                self.incoming_files[fid]["file"].close()
                path = self.incoming_files[fid]["path"]
                del self.incoming_files[fid]
                self.append_system(f"Файл сохранен: {path}")

    # --- Звонки (Интеграция) ---
    def start_call(self):
        try:
            conf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "p2p_conf.pyw")
            subprocess.Popen([sys.executable, conf_path, "--user", self.main.username, "--create"])
            
            # Рассылаем приглашения всем участникам чата
            self.node.send_to_chat(self.chat_id, {"type": "call_invite"}, self.ips)
            
            time_str = datetime.now().strftime("%H:%M")
            msg_html = f"""
            <div align="right" style="margin-bottom: 8px;">
                <span style='color: gray; font-size: 11px;'>{time_str}</span> <span style='color: #a6e3a1; font-weight: bold;'>Вы</span><br>
                <table style="background-color: rgb(30, 31, 32); margin-top: 4px; border-radius: 5px;" cellspacing="0" cellpadding="10">
                    <tr><td>Вы начали конференцию в приложении Telemax: Calls. Приглашения отправлены.</td></tr>
                </table>
            </div>
            """
            self.append_message(msg_html)
        except Exception as e:
            self.append_system(f"Ошибка запуска сервера звонков: {e}")

class MessengerWindow(QMainWindow):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle(f"Telemax - {self.username}")
        self.resize(1000, 700)
        self.setStyleSheet(DARK_STYLESHEET)
        
        self.node = P2PNode(username)
        self.chats = {} # chat_id -> ChatWidget

        self.save_dir = os.path.join(str(Path.home()), ".telemax_data")
        os.makedirs(self.save_dir, exist_ok=True)

        self.init_ui()
        
        self.node.message_received.connect(self.route_message)
        self.node.handshake_complete.connect(lambda ip: self.statusBar().showMessage(f"Подключен: {ip}", 3000))
        self.node.connection_error.connect(lambda msg: self.statusBar().showMessage(msg, 3000))

        self.load_state()

    def save_state(self):
        state = {}
        for chat_id, cw in self.chats.items():
            if cw.is_burn: continue
            state[chat_id] = {
                "name": cw.name,
                "ips": cw.ips,
                "history": cw.message_history
            }
        try:
            with open(os.path.join(self.save_dir, "chats.json"), "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False)
        except: pass

    def load_state(self):
        path = os.path.join(self.save_dir, "chats.json")
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    state = json.load(f)
                    for chat_id, data in state.items():
                        self.add_chat(chat_id, data["name"], data["ips"], False)
                        self.chats[chat_id].message_history = data.get("history", [])
                        for html_msg in self.chats[chat_id].message_history:
                            self.chats[chat_id].chat_display.append(html_msg)
            except: pass

    def init_ui(self):
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.setCentralWidget(splitter)

        # Левая панель (Список чатов)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0,0,0,0)
        
        btn_new_chat = QPushButton("+ Новый Чат")
        btn_new_chat.clicked.connect(self.create_chat)
        left_layout.addWidget(btn_new_chat)
        
        self.chat_list = QListWidget()
        self.chat_list.currentRowChanged.connect(self.switch_chat)
        left_layout.addWidget(self.chat_list)
        
        # Правая панель (Область чата)
        self.chat_stack = QStackedWidget()
        
        empty_lbl = QLabel("Выберите чат или создайте новый")
        empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.chat_stack.addWidget(empty_lbl)

        splitter.addWidget(left_panel)
        splitter.addWidget(self.chat_stack)
        splitter.setSizes([250, 750])

    def create_chat(self):
        dialog = NewChatDialog()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            name, ips, is_burn = dialog.get_data()
            if not ips: return QMessageBox.warning(self, "Ошибка", "Укажите хотя бы 1 IP.")
            
            chat_id = str(uuid.uuid4())
            self.add_chat(chat_id, name, ips, is_burn)

            # Отправляем приглашение
            self.node.send_to_chat(chat_id, {
                "type": "chat_invite", "name": name, "ips": ips, "is_burn": is_burn
            }, ips)

    def add_chat(self, chat_id, name, ips, is_burn):
        if chat_id in self.chats: return
        
        cw = ChatWidget(chat_id, name, ips, is_burn, self)
        self.chats[chat_id] = cw
        self.chat_stack.addWidget(cw)
        
        item = QListWidgetItem(f"🔥 {name}" if is_burn else name)
        item.setData(Qt.ItemDataRole.UserRole, chat_id)
        self.chat_list.addItem(item)
        self.chat_list.setCurrentItem(item)
        
        for ip in ips: self.node.send_handshake(ip)

    def switch_chat(self, index):
        if index < 0: return
        item = self.chat_list.item(index)
        chat_id = item.data(Qt.ItemDataRole.UserRole)
        self.chat_stack.setCurrentWidget(self.chats[chat_id])

    def route_message(self, sender_ip, chat_id, payload):
        mtype = payload.get("type")
        
        if mtype == "chat_invite":
            # Авто-добавление чата при приглашении
            ips = payload.get("ips", [])
            if sender_ip not in ips: ips.append(sender_ip)
            if "127.0.0.1" in ips: ips.remove("127.0.0.1")
            
            self.add_chat(chat_id, payload.get("name", "Group"), ips, payload.get("is_burn", False))
            self.chats[chat_id].append_system(f"{payload.get('username', sender_ip)} пригласил вас.")
            return

        if chat_id in self.chats:
            self.chats[chat_id].handle_incoming(sender_ip, payload)

    def closeEvent(self, event):
        self.node.running = False
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    login = ConnectDialog()
    if login.exec() == QDialog.DialogCode.Accepted:
        username = login.get_name()
        window = MessengerWindow(username)
        window.show()
        sys.exit(app.exec())