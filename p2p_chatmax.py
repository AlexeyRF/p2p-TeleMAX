import sys
import socket
import threading
import json
import os
import uuid
import html
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextBrowser, QLineEdit, QPushButton, 
                             QFileDialog, QMessageBox, QLabel, QDialog)
from PyQt6.QtCore import pyqtSignal, QObject, Qt, QUrl, QThread, QBuffer, QIODevice
from PyQt6.QtGui import QImage
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import base64 as b64


def format_size(size_bytes):
    for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} ТБ"


class SaveFileThread(QThread):
    finished = pyqtSignal(str, bool, str) 

    def __init__(self, filename, b64_content, save_dir):
        super().__init__()
        self.filename = filename
        self.b64_content = b64_content
        self.save_dir = save_dir

    def run(self):
        try:
            os.makedirs(self.save_dir, exist_ok=True)
            secure_name = os.path.basename(self.filename)
            save_path = os.path.join(self.save_dir, secure_name)
            base, ext = os.path.splitext(secure_name)
            counter = 1
            while os.path.exists(save_path):
                save_path = os.path.join(self.save_dir, f"{base}_{counter}{ext}")
                counter += 1

            with open(save_path, "wb") as f:
                f.write(b64.b64decode(self.b64_content))

            self.finished.emit(secure_name, True, save_path)
        except Exception as e:
            self.finished.emit(self.filename, False, str(e))

class P2PNode(QObject):
    message_received = pyqtSignal(str, dict)
    handshake_complete = pyqtSignal(str)

    def __init__(self, port=5555):
        super().__init__()
        self.port = port
        self.running = True
        self.encryption_keys = {} 
        
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        self.server_thread = threading.Thread(target=self.start_server, daemon=True)
        self.server_thread.start()

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(('0.0.0.0', self.port))
        except Exception as e:
            print(f"Ошибка бинда: {e}")
            return
            
        server.listen(10)
        while self.running:
            try:
                conn, addr = server.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr[0]), daemon=True).start()
            except: break

    def handle_client(self, conn, addr):
        try:
            data = b""
            while True:
                packet = conn.recv(1024 * 1024)
                if not packet: break
                data += packet
                if len(data) > 75 * 1024 * 1024: 
                    conn.close()
                    return
            
            if not data: return

            try:
                payload = json.loads(data.decode('utf-8'))
                if payload.get("type") == "handshake":
                    self.process_handshake(addr, payload.get("pub_key"))
                    return
            except: pass 

            if addr in self.encryption_keys:
                decrypted_data = self.encryption_keys[addr].decrypt(data).decode('utf-8')
                self.message_received.emit(addr, json.loads(decrypted_data))
        except Exception as e:
            print(f"Ошибка обработки от {addr}: {e}")
        finally:
            conn.close()

    def process_handshake(self, addr, peer_pub_key_b64):
        peer_pub_bytes = b64.b64decode(peer_pub_key_b64)
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        shared_key = self.private_key.exchange(peer_public_key)
        
        import hashlib
        derived_key = b64.urlsafe_b64encode(hashlib.sha256(shared_key).digest())
        self.encryption_keys[addr] = Fernet(derived_key)
        self.handshake_complete.emit(addr)

    def send_handshake(self, ip_list):
        pub_b64 = b64.b64encode(self.public_key_bytes).decode('utf-8')
        payload = {"type": "handshake", "pub_key": pub_b64}
        self.send_raw(ip_list, payload, encrypt=False)

    def send_raw(self, ip_list, payload_dict, encrypt=True):
        def _send():
            for ip in ip_list:
                try:
                    raw_data = json.dumps(payload_dict).encode('utf-8')
                    if encrypt and ip in self.encryption_keys:
                        data_to_send = self.encryption_keys[ip].encrypt(raw_data)
                    else:
                        data_to_send = raw_data

                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.settimeout(5)
                    client.connect((ip, self.port))
                    client.sendall(data_to_send)
                    client.close()
                except Exception as e:
                    print(f"Ошибка отправки на {ip}: {e}")
        threading.Thread(target=_send, daemon=True).start()


class ConnectDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Вход в Telemax")
        self.setFixedSize(300, 120)
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Введите IP адреса собеседников:"))
        self.ips_input = QLineEdit()
        self.ips_input.setPlaceholderText("192.168.1.5")
        layout.addWidget(self.ips_input)
        
        self.connect_btn = QPushButton("Войти в чат")
        self.connect_btn.clicked.connect(self.accept)
        layout.addWidget(self.connect_btn)

    def get_ips(self):
        return [ip.strip() for ip in self.ips_input.text().split(",") if ip.strip()]

class MessengerWindow(QMainWindow):
    def __init__(self, target_ips):
        super().__init__()
        self.setWindowTitle("Telemax P2P")
        self.resize(800, 550)
        
        self.node = P2PNode()
        self.target_ips = target_ips
        
        self.file_cache = {} 
        self.active_threads = [] 

        self.init_ui()
        
        self.node.message_received.connect(self.display_message)
        self.node.handshake_complete.connect(self.on_handshake_done)

        self.chat_display.append("<i>[Система]: Инициализация соединения...</i>")
        self.node.send_handshake(self.target_ips)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.chat_display = QTextBrowser()
        self.chat_display.setOpenLinks(False)
        self.chat_display.anchorClicked.connect(self.handle_link_click)
        layout.addWidget(self.chat_display)

        input_layout = QHBoxLayout()
        self.msg_input = QLineEdit()
        self.msg_input.returnPressed.connect(self.send_text)
        
        send_btn = QPushButton("Отправить")
        send_btn.clicked.connect(self.send_text)
        
        attach_btn = QPushButton("📎")
        attach_btn.setFixedWidth(40)
        attach_btn.clicked.connect(self.send_file)

        input_layout.addWidget(attach_btn)
        input_layout.addWidget(self.msg_input)
        input_layout.addWidget(send_btn)
        layout.addLayout(input_layout)

    def on_handshake_done(self, ip):
        self.chat_display.append(f"<small style='color:green'>[Система]: Канал с {ip} защищен.</small>")

    def send_text(self):
        text = self.msg_input.text().strip()
        if not text: return
        
        payload = {"type": "text", "content": text}
        self.node.send_raw(self.target_ips, payload)
        
        safe_text = html.escape(text)
        self.chat_display.append(f"<b>Вы:</b> {safe_text}")
        self.msg_input.clear()

    def send_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выбрать файл")
        if not file_path: return

        
        file_size = os.path.getsize(file_path)
        if file_size > 50 * 1024 * 1024: 
            QMessageBox.warning(self, "Ошибка", "Размер файла превышает лимит (50 МБ).")
            return

        filename = os.path.basename(file_path)
        
       
        with open(file_path, "rb") as f:
            file_data = b64.b64encode(f.read()).decode('utf-8')

        preview_b64 = ""
        ext = filename.lower().split('.')[-1]
        if ext in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
            img = QImage(file_path)
            if not img.isNull():
                img = img.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                ba = QBuffer()
                ba.open(QIODevice.OpenModeFlag.WriteOnly)
                img.save(ba, "PNG")
                preview_b64 = b64.b64encode(ba.data()).decode('utf-8')

        file_id = str(uuid.uuid4())
        payload = {
            "type": "file",
            "file_id": file_id,
            "filename": filename,
            "size": file_size,
            "content": file_data,
            "preview": preview_b64
        }
        self.node.send_raw(self.target_ips, payload)
        
        preview_html = f'<br><img src="data:image/png;base64,{preview_b64}">' if preview_b64 else ''
        self.chat_display.append(f"<b>Вы отправили файл:</b> {filename} ({format_size(file_size)}){preview_html}")

    def display_message(self, sender_ip, payload):
        msg_type = payload.get("type")
        
        if msg_type == "text":

            content = html.escape(payload.get("content", ""))
            self.chat_display.append(f"<b>{sender_ip}:</b> {content}")
            
        elif msg_type == "file":

            filename = os.path.basename(payload.get("filename", "file"))
            file_size = payload.get("size", 0)
            content = payload.get("content", "")
            preview_b64 = payload.get("preview", "")
            file_id = payload.get("file_id", str(uuid.uuid4()))


            self.file_cache[file_id] = {
                "filename": filename,
                "content": content
            }

            preview_html = f'<br><img src="data:image/png;base64,{preview_b64}">' if preview_b64 else ''
            size_str = format_size(file_size)
            

            link_html = f'<br><a href="save://{file_id}">💾 Скачать {filename} ({size_str})</a>'
            
            self.chat_display.append(f"<b>{sender_ip}:</b> отправил медиафайл{preview_html}{link_html}")

    def handle_link_click(self, url: QUrl):
        if url.scheme() == "save":
            file_id = url.host()
            if file_id in self.file_cache:
                file_info = self.file_cache[file_id]
                downloads_dir = os.path.join(str(Path.home()), "Downloads", "telemax")
                
                self.chat_display.append(f"<i>Начинаю сохранение {file_info['filename']}...</i>")
                

                thread = SaveFileThread(file_info['filename'], file_info['content'], downloads_dir)
                thread.finished.connect(self.on_file_saved)
                self.active_threads.append(thread)
                thread.start()
            else:
                QMessageBox.warning(self, "Ошибка", "Данные файла больше недоступны в памяти.")

    def on_file_saved(self, filename, success, message):
        if success:
            self.chat_display.append(f"<small style='color:green'>✅ Файл <b>{filename}</b> сохранен в загрузки!</small>")
        else:
            self.chat_display.append(f"<small style='color:red'>❌ Ошибка при сохранении {filename}: {message}</small>")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    login = ConnectDialog()
    if login.exec() == QDialog.DialogCode.Accepted:
        ips = login.get_ips()
        if not ips:
            ips = ["127.0.0.1"]
            
        window = MessengerWindow(ips)
        window.show()
        sys.exit(app.exec())