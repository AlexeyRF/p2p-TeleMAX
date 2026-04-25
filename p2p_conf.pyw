import sys
import socket
import threading
import struct
import pickle
import time
import argparse
import numpy as np
import cv2
import pyaudio
import mss
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                             QTextEdit, QListWidget, QListWidgetItem, QSlider, 
                             QStackedWidget, QGridLayout, QMessageBox, QScrollArea, QFrame)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QImage, QPixmap

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

PORT = 45555
CHUNK_SIZE = 1024
AUDIO_FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 16000
VIDEO_WIDTH = 640
VIDEO_HEIGHT = 480
JPEG_QUALITY = 85

DARK_STYLESHEET = """
QMainWindow, QWidget#MainContainer { background-color: rgb(19, 19, 20); color: #cdd6f4; font-family: 'Segoe UI', Arial, sans-serif; }
QWidget { background-color: transparent; color: #cdd6f4; font-family: 'Segoe UI', Arial, sans-serif; }
QPushButton { background-color: rgb(40, 42, 44); color: #cdd6f4; border: 1px solid rgb(30, 31, 32); border-radius: 5px; padding: 8px 15px; font-weight: bold; }
QPushButton:hover { background-color: rgb(30, 31, 32); }
QPushButton:disabled { background-color: rgb(28, 28, 28); color: #6c7086; }
QPushButton.danger { background-color: #f38ba8; color: #11111b; border: none; }
QPushButton.danger:hover { background-color: #eba0ac; }
QPushButton.toggle-on { background-color: #a6e3a1; color: #11111b; border: none; }
QLineEdit, QTextEdit, QListWidget, QScrollArea { background-color: rgb(30, 31, 32); border: 1px solid rgb(40, 42, 44); border-radius: 5px; padding: 5px; color: #cdd6f4; }
QSlider::groove:horizontal { border: 1px solid rgb(40, 42, 44); height: 8px; background: rgb(30, 31, 32); margin: 2px 0; border-radius: 4px; }
QSlider::handle:horizontal { background: rgb(100, 110, 130); border: 1px solid rgb(100, 110, 130); width: 14px; margin: -4px 0; border-radius: 7px; }
QFrame#VideoFrame { border: 2px solid rgb(40, 42, 44); border-radius: 8px; background-color: rgb(28, 28, 28); }
#TitleBar { background-color: rgb(28, 28, 28); }
#TitleBar QPushButton { background-color: transparent; border: none; padding: 8px 15px; border-radius: 0px; margin: 0px; font-weight: normal; }
#TitleBar QPushButton:hover { background-color: rgb(40, 42, 44); }
#TitleBar QPushButton#btn_close:hover { background-color: #f38ba8; color: #11111b; }
"""

def send_data(sock, data):
    try:
        msg = struct.pack('>I', len(data)) + data
        sock.sendall(msg)
        return True
    except:
        return False

def recv_data(sock):
    try:
        raw_msglen = recvall(sock, 4)
        if not raw_msglen: return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return recvall(sock, msglen)
    except:
        return None

def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
        data.extend(packet)
    return bytes(data)

class CryptoManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.fernet = None

    def generate_rsa_keys(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def decrypt_rsa(self, encrypted_data):
        return self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    def generate_symmetric_key(self):
        key = Fernet.generate_key()
        self.fernet = Fernet(key)
        return key

    def encrypt_symmetric_key(self, client_pub_key_bytes, sym_key):
        client_pub_key = serialization.load_pem_public_key(client_pub_key_bytes)
        return client_pub_key.encrypt(
            sym_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    def set_symmetric_key(self, key):
        self.fernet = Fernet(key)

    def encrypt(self, data: bytes):
        if not self.fernet: return data
        return self.fernet.encrypt(data)

    def decrypt(self, data: bytes):
        if not self.fernet: return data
        return self.fernet.decrypt(data)

class ServerThread(QThread):
    def __init__(self):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(('0.0.0.0', PORT))
        self.sock.listen(10)
        self.clients = {}
        self.running = True
        self.sym_key = CryptoManager().generate_symmetric_key()
        self.fernet = Fernet(self.sym_key)
        self.lock = threading.Lock()

    def run(self):
        while self.running:
            try:
                self.sock.settimeout(1)
                conn, addr = self.sock.accept()
                threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def handle_client(self, conn):
        try:
            pub_key_bytes = recv_data(conn)
            if not pub_key_bytes: return
            
            cm = CryptoManager()
            enc_sym_key = cm.encrypt_symmetric_key(pub_key_bytes, self.sym_key)
            send_data(conn, enc_sym_key)

            enc_info = recv_data(conn)
            info = pickle.loads(self.fernet.decrypt(enc_info))
            client_id = info['id']
            requested_name = info['name']
            
            with self.lock:
                existing_names = [v['name'] for v in self.clients.values()]
                final_name = requested_name
                counter = 1
                while final_name in existing_names:
                    final_name = f"{requested_name}_{counter}"
                    counter += 1
                self.clients[conn] = {'id': client_id, 'name': final_name}
            
            name_ack = self.fernet.encrypt(pickle.dumps({'type': 'name_ack', 'name': final_name}))
            send_data(conn, name_ack)
            
            self.broadcast({'type': 'sys', 'msg': f"{final_name} присоединился"}, exclude=conn)

            while self.running:
                enc_data = recv_data(conn)
                if not enc_data: break
                
                data = pickle.loads(self.fernet.decrypt(enc_data))
                if data.get('type') == 'ping':
                    pong = self.fernet.encrypt(pickle.dumps({'type': 'pong'}))
                    send_data(conn, pong)
                    continue

                self.broadcast_raw(enc_data, exclude=conn)

        except Exception:
            pass
        finally:
            with self.lock:
                if conn in self.clients:
                    name = self.clients[conn]['name']
                    del self.clients[conn]
                    self.broadcast({'type': 'sys', 'msg': f"{name} покинул комнату"})
            conn.close()

    def broadcast(self, obj, exclude=None):
        raw = self.fernet.encrypt(pickle.dumps(obj))
        self.broadcast_raw(raw, exclude)

    def broadcast_raw(self, raw_data, exclude=None):
        with self.lock:
            for c in list(self.clients.keys()):
                if c != exclude:
                    try:
                        send_data(c, raw_data)
                    except:
                        pass

    def stop(self):
        self.running = False
        self.sock.close()

class ClientManager(QThread):
    connected = pyqtSignal(bool, str)
    video_received = pyqtSignal(str, object)
    video_stopped = pyqtSignal(str)
    audio_received = pyqtSignal(str, object)
    chat_received = pyqtSignal(str, str)
    sys_msg_received = pyqtSignal(str)
    participant_update = pyqtSignal(str, str, bool)
    latency_update = pyqtSignal(int)
    name_updated = pyqtSignal(str)
    
    def __init__(self, ip, name):
        super().__init__()
        self.ip = ip
        self.name = name
        self.client_id = str(time.time())
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.crypto = CryptoManager()
        self.running = True
        self.participants = {}
        self.user_volumes = {}
        self.user_mutes = {}

    def run(self):
        try:
            self.sock.connect((self.ip, PORT))
            
            pub_key = self.crypto.generate_rsa_keys()
            send_data(self.sock, pub_key)
            
            enc_sym_key = recv_data(self.sock)
            sym_key = self.crypto.decrypt_rsa(enc_sym_key)
            self.crypto.set_symmetric_key(sym_key)
            
            info = {'id': self.client_id, 'name': self.name}
            self.send_obj(info)
            
            self.connected.emit(True, "")
            
            threading.Thread(target=self.ping_loop, daemon=True).start()

            while self.running:
                enc_data = recv_data(self.sock)
                if not enc_data: break
                
                data = pickle.loads(self.crypto.decrypt(enc_data))
                self.process_incoming(data)
                
        except Exception as e:
            self.connected.emit(False, str(e))
        finally:
            self.stop()

    def process_incoming(self, data):
        mtype = data.get('type')
        sender_id = data.get('sender_id')
        sender_name = data.get('sender_name', 'Unknown')
        
        if mtype == 'name_ack':
            self.name = data['name']
            self.name_updated.emit(self.name)
            return

        if sender_id and sender_id != self.client_id:
            if sender_id not in self.participants:
                self.participants[sender_id] = sender_name
                self.participant_update.emit(sender_id, sender_name, False)
                self.user_volumes[sender_id] = 1.0
                self.user_mutes[sender_id] = False

        if mtype == 'video':
            self.video_received.emit(sender_id, data['data'])
        elif mtype == 'video_stop':
            self.video_stopped.emit(sender_id)
        elif mtype == 'audio':
            if not self.user_mutes.get(sender_id, False):
                vol = self.user_volumes.get(sender_id, 1.0)
                audio_data = np.frombuffer(data['data'], dtype=np.int16)
                if vol != 1.0:
                    audio_data = (audio_data * vol).astype(np.int16)
                self.audio_received.emit(sender_id, audio_data.tobytes())
        elif mtype == 'chat':
            self.chat_received.emit(sender_name, data['msg'])
        elif mtype == 'sys':
            self.sys_msg_received.emit(data['msg'])
        elif mtype == 'hand':
            self.participant_update.emit(sender_id, sender_name, data['state'])
        elif mtype == 'pong':
            pass

    def ping_loop(self):
        while self.running:
            start = time.time()
            self.send_obj({'type': 'ping'})
            time.sleep(2)
            latency = int((time.time() - start - 2) * 1000)
            if latency < 0: latency = abs(latency)
            self.latency_update.emit(latency)

    def send_obj(self, obj):
        if not self.running: return
        obj['sender_id'] = self.client_id
        obj['sender_name'] = self.name
        raw = self.crypto.encrypt(pickle.dumps(obj))
        try:
            send_data(self.sock, raw)
        except:
            self.stop()

    def stop(self):
        self.running = False
        try: self.sock.close()
        except: pass

class AudioEngine(QThread):
    def __init__(self, client):
        super().__init__()
        self.client = client
        self.p = pyaudio.PyAudio()
        self.running = True
        self.mic_muted = False
        
        self.play_stream = self.p.open(format=AUDIO_FORMAT, channels=CHANNELS, 
                                       rate=RATE, output=True, frames_per_buffer=CHUNK_SIZE)
        self.client.audio_received.connect(self.play_audio)

    def run(self):
        stream = self.p.open(format=AUDIO_FORMAT, channels=CHANNELS, rate=RATE, 
                             input=True, frames_per_buffer=CHUNK_SIZE)
        while self.running:
            try:
                data = stream.read(CHUNK_SIZE, exception_on_overflow=False)
                if not self.mic_muted:
                    self.client.send_obj({'type': 'audio', 'data': data})
            except Exception:
                pass
        stream.stop_stream()
        stream.close()

    def play_audio(self, sender_id, data):
        if self.running:
            try: self.play_stream.write(data)
            except: pass

    def stop(self):
        self.running = False
        self.play_stream.stop_stream()
        self.play_stream.close()
        self.p.terminate()

class VideoEngine(QThread):
    frame_ready = pyqtSignal(object)

    def __init__(self, client):
        super().__init__()
        self.client = client
        self.running = True
        self.mode = 'none'
        self.cap = None
        self.sct = mss.MSS()

    def run(self):
        while self.running:
            if self.mode == 'none':
                if self.cap:
                    self.cap.release()
                    self.cap = None
                time.sleep(0.1)
                continue

            frame = None
            if self.mode == 'camera':
                if not self.cap or not self.cap.isOpened():
                    self.cap = cv2.VideoCapture(0)
                    self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, VIDEO_WIDTH)
                    self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, VIDEO_HEIGHT)
                ret, frame = self.cap.read()
                if ret:
                    frame = cv2.flip(frame, 1)
            elif self.mode == 'screen':
                if self.cap:
                    self.cap.release()
                    self.cap = None
                monitor = self.sct.monitors[1]
                sct_img = self.sct.grab(monitor)
                frame = np.array(sct_img)
                frame = cv2.cvtColor(frame, cv2.COLOR_BGRA2BGR)
                frame = cv2.resize(frame, (VIDEO_WIDTH, VIDEO_HEIGHT))

            if frame is not None:
                rgb_image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                h, w, ch = rgb_image.shape
                qimg = QImage(rgb_image.data, w, h, ch * w, QImage.Format_RGB888)
                self.frame_ready.emit(qimg)

                _, buffer = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_QUALITY])
                self.client.send_obj({'type': 'video', 'data': buffer.tobytes()})
                
            time.sleep(0.05)

        if self.cap: self.cap.release()

    def set_mode(self, mode):
        self.mode = mode

    def stop(self):
        self.running = False

class UserVideoWidget(QFrame):
    def __init__(self, name):
        super().__init__()
        self.setObjectName("VideoFrame")
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        
        self.video_label = QLabel()
        self.video_label.setAlignment(Qt.AlignCenter)
        self.video_label.setMinimumSize(320, 240)
        self.video_label.setStyleSheet("background-color: #000; border-radius: 5px;")
        
        self.name_label = QLabel(name)
        self.name_label.setAlignment(Qt.AlignCenter)
        self.name_label.setStyleSheet("font-weight: bold; background: rgba(0,0,0,150); padding: 2px;")
        
        layout.addWidget(self.video_label, 1)
        layout.addWidget(self.name_label, 0)
        self.setLayout(layout)

    def update_frame(self, data):
        np_arr = np.frombuffer(data, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if img is not None:
            rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            h, w, ch = rgb.shape
            qimg = QImage(rgb.data, w, h, ch * w, QImage.Format_RGB888)
            self.video_label.setPixmap(QPixmap.fromImage(qimg).scaled(
                self.video_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))

class ParticipantItem(QWidget):
    def __init__(self, client_mgr, user_id, name):
        super().__init__()
        self.client_mgr = client_mgr
        self.user_id = user_id
        
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.lbl_name = QLabel(name)
        
        self.btn_mute = QPushButton("Mute")
        self.btn_mute.setCheckable(True)
        self.btn_mute.clicked.connect(self.toggle_mute)
        
        self.slider_vol = QSlider(Qt.Horizontal)
        self.slider_vol.setRange(0, 100)
        self.slider_vol.setValue(100)
        self.slider_vol.valueChanged.connect(self.change_volume)
        
        layout.addWidget(self.lbl_name)
        layout.addWidget(self.slider_vol)
        layout.addWidget(self.btn_mute)
        self.setLayout(layout)

    def toggle_mute(self, checked):
        self.client_mgr.user_mutes[self.user_id] = checked
        self.btn_mute.setText("Unmute" if checked else "Mute")
        self.btn_mute.setStyleSheet("background-color: #f38ba8;" if checked else "")

    def change_volume(self, val):
        self.client_mgr.user_volumes[self.user_id] = val / 100.0

    def set_hand(self, raised):
        txt = f"✋ {self.lbl_name.text().replace('✋ ', '')}" if raised else self.lbl_name.text().replace('✋ ', '')
        self.lbl_name.setText(txt)

class TitleBar(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.setObjectName("TitleBar")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 0, 0, 0)
        layout.setSpacing(0)
        
        self.title = QLabel("Telemax: Calls")
        self.title.setStyleSheet("font-weight: bold; font-size: 13px; color: #cdd6f4;")
        
        self.btn_min = QPushButton("—")
        self.btn_max = QPushButton("☐")
        self.btn_close = QPushButton("✕")
        self.btn_close.setObjectName("btn_close")
        
        self.btn_min.clicked.connect(self.parent.showMinimized)
        self.btn_max.clicked.connect(self.toggle_max)
        self.btn_close.clicked.connect(self.parent.close)
        
        layout.addWidget(self.title)
        layout.addStretch()
        layout.addWidget(self.btn_min)
        layout.addWidget(self.btn_max)
        layout.addWidget(self.btn_close)
        
        self.start_pos = None

    def toggle_max(self):
        if self.parent.isMaximized():
            self.parent.showNormal()
        else:
            self.parent.showMaximized()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.start_pos = event.globalPos() - self.parent.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton and self.start_pos:
            self.parent.move(event.globalPos() - self.start_pos)
            event.accept()

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.toggle_max()
            event.accept()

class MainWindow(QMainWindow):
    def __init__(self, start_args=None):
        super().__init__()
        self.setWindowTitle("Telemax: Calls")
        self.resize(1000, 700)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setStyleSheet(DARK_STYLESHEET)
        
        self.server = None
        self.client = None
        self.audio_engine = None
        self.video_engine = None
        
        self.main_container = QWidget()
        self.main_container.setObjectName("MainContainer")
        self.main_layout = QVBoxLayout(self.main_container)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        
        self.title_bar = TitleBar(self)
        self.main_layout.addWidget(self.title_bar)
        
        self.stack = QStackedWidget()
        self.main_layout.addWidget(self.stack)
        
        self.setCentralWidget(self.main_container)
        
        self.init_login_ui()
        self.init_room_ui()
        
        self.stack.setCurrentIndex(0)

        if start_args:
            if start_args.user:
                self.inp_name.setText(start_args.user)
            if start_args.create:
                self.host_room()
            elif start_args.ip:
                self.inp_ip.setText(start_args.ip)
                self.join_room()

    def init_login_ui(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setAlignment(Qt.AlignCenter)
        
        self.inp_name = QLineEdit()
        self.inp_name.setPlaceholderText("Ваше имя")
        self.inp_name.setText(f"User_{int(time.time())%1000}")
        self.inp_name.setFixedWidth(300)
        
        self.inp_ip = QLineEdit()
        self.inp_ip.setPlaceholderText("IP создателя комнаты (пусто если создаете вы)")
        self.inp_ip.setFixedWidth(300)
        
        btn_host = QPushButton("Создать комнату")
        btn_host.clicked.connect(self.host_room)
        
        btn_join = QPushButton("Присоединиться")
        btn_join.clicked.connect(self.join_room)
        
        layout.addWidget(self.inp_name)
        layout.addWidget(self.inp_ip)
        layout.addWidget(btn_host)
        layout.addWidget(btn_join)
        
        self.stack.addWidget(w)

    def init_room_ui(self):
        w = QWidget()
        main_layout = QHBoxLayout(w)
        
        video_area = QScrollArea()
        video_area.setWidgetResizable(True)
        video_area.setStyleSheet("border: none; background: rgb(19, 19, 20);")
        video_widget = QWidget()
        self.video_grid = QGridLayout(video_widget)
        video_area.setWidget(video_widget)
        
        sidebar = QVBoxLayout()
        sidebar.setContentsMargins(10, 0, 0, 0)
        
        self.lbl_net = QLabel("Сеть: Ожидание...")
        self.lbl_net.setStyleSheet("color: #f9e2af; font-weight: bold;")
        
        lbl_part = QLabel("Участники:")
        self.list_part = QListWidget()
        self.list_part.setFixedWidth(250)
        
        lbl_chat = QLabel("Чат:")
        self.txt_chat = QTextEdit()
        self.txt_chat.setReadOnly(True)
        self.txt_chat.setFixedWidth(250)
        
        chat_input_layout = QHBoxLayout()
        self.inp_chat = QLineEdit()
        self.inp_chat.returnPressed.connect(self.send_chat)
        btn_send = QPushButton("->")
        btn_send.setFixedWidth(40)
        btn_send.clicked.connect(self.send_chat)
        chat_input_layout.addWidget(self.inp_chat)
        chat_input_layout.addWidget(btn_send)
        
        sidebar.addWidget(self.lbl_net)
        sidebar.addWidget(lbl_part)
        sidebar.addWidget(self.list_part, 1)
        sidebar.addWidget(lbl_chat)
        sidebar.addWidget(self.txt_chat, 2)
        sidebar.addLayout(chat_input_layout)
        
        toolbar = QHBoxLayout()
        self.btn_mic = QPushButton("Микрофон: ВКЛ")
        self.btn_mic.clicked.connect(self.toggle_mic)
        self.btn_cam = QPushButton("Камера: ВЫКЛ")
        self.btn_cam.clicked.connect(self.toggle_cam)
        self.btn_scr = QPushButton("Экран: ВЫКЛ")
        self.btn_scr.clicked.connect(self.toggle_scr)
        self.btn_hand = QPushButton("✋ Поднять руку")
        self.btn_hand.setCheckable(True)
        self.btn_hand.clicked.connect(self.toggle_hand)
        btn_leave = QPushButton("Завершить звонок")
        btn_leave.setObjectName("leave")
        btn_leave.setStyleSheet("background-color: #f38ba8; color: #11111b;")
        btn_leave.clicked.connect(self.leave_room)
        
        toolbar.addWidget(self.btn_mic)
        toolbar.addWidget(self.btn_cam)
        toolbar.addWidget(self.btn_scr)
        toolbar.addWidget(self.btn_hand)
        toolbar.addStretch()
        toolbar.addWidget(btn_leave)
        
        left_layout = QVBoxLayout()
        left_layout.addWidget(video_area, 1)
        left_layout.addLayout(toolbar, 0)
        
        main_layout.addLayout(left_layout, 1)
        main_layout.addLayout(sidebar, 0)
        
        self.stack.addWidget(w)
        
        self.video_widgets = {}
        self.participant_widgets = {}

    def host_room(self):
        name = self.inp_name.text().strip()
        if not name: return QMessageBox.warning(self, "Ошибка", "Введите имя!")
        
        self.server = ServerThread()
        self.server.start()
        
        self.connect_client('127.0.0.1', name)

    def join_room(self):
        name = self.inp_name.text().strip()
        ip = self.inp_ip.text().strip()
        if not name or not ip: return QMessageBox.warning(self, "Ошибка", "Введите имя и IP!")
        self.connect_client(ip, name)

    def connect_client(self, ip, name):
        self.client = ClientManager(ip, name)
        self.client.connected.connect(self.on_connected)
        self.client.video_received.connect(self.on_video)
        self.client.video_stopped.connect(self.on_video_stopped)
        self.client.chat_received.connect(self.on_chat)
        self.client.sys_msg_received.connect(self.on_sys_msg)
        self.client.participant_update.connect(self.on_participant_update)
        self.client.latency_update.connect(self.on_latency)
        self.client.name_updated.connect(self.on_name_updated)
        self.client.start()

    def on_connected(self, success, error):
        if success:
            self.stack.setCurrentIndex(1)
            self.txt_chat.clear()
            self.list_part.clear()
            self.video_widgets.clear()
            self.participant_widgets.clear()
            
            self.add_video_widget(self.client.client_id, self.client.name + " (Вы)")
            
            self.audio_engine = AudioEngine(self.client)
            self.audio_engine.start()
            
            self.video_engine = VideoEngine(self.client)
            self.video_engine.frame_ready.connect(self.update_local_video)
            self.video_engine.start()
            
            self.btn_mic.setText("Микрофон: ВКЛ")
            self.btn_mic.setStyleSheet("")
        else:
            QMessageBox.critical(self, "Ошибка подключения", f"Не удалось подключиться:\n{error}")
            if self.server:
                self.server.stop()
                self.server = None
            self.stack.setCurrentIndex(0)

    def on_name_updated(self, new_name):
        if self.client.client_id in self.video_widgets:
            self.video_widgets[self.client.client_id].name_label.setText(new_name + " (Вы)")

    def add_video_widget(self, uid, name):
        if uid in self.video_widgets: return
        vw = UserVideoWidget(name)
        self.video_widgets[uid] = vw
        
        count = len(self.video_widgets) - 1
        row = count // 2
        col = count % 2
        self.video_grid.addWidget(vw, row, col)

    def on_video(self, sender_id, data):
        if sender_id in self.video_widgets:
            self.video_widgets[sender_id].update_frame(data)

    def update_local_video(self, qimg):
        if self.client.client_id in self.video_widgets:
            vw = self.video_widgets[self.client.client_id]
            vw.video_label.setPixmap(QPixmap.fromImage(qimg).scaled(
                vw.video_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def on_chat(self, sender, msg):
        self.txt_chat.append(f"<b>{sender}</b>: {msg}")

    def on_sys_msg(self, msg):
        self.txt_chat.append(f"<i style='color:#a6adc8;'>Система: {msg}</i>")

    def on_participant_update(self, uid, name, hand_raised):
        if uid not in self.participant_widgets and uid != self.client.client_id:
            item = QListWidgetItem(self.list_part)
            pw = ParticipantItem(self.client, uid, name)
            item.setSizeHint(pw.sizeHint())
            self.list_part.setItemWidget(item, pw)
            self.participant_widgets[uid] = (item, pw)
            self.add_video_widget(uid, name)
        
        if uid in self.participant_widgets:
            _, pw = self.participant_widgets[uid]
            pw.set_hand(hand_raised)

    def on_latency(self, ms):
        self.lbl_net.setText(f"Сеть: {ms} мс")
        if ms < 50: self.lbl_net.setStyleSheet("color: #a6e3a1; font-weight: bold;")
        elif ms < 150: self.lbl_net.setStyleSheet("color: #f9e2af; font-weight: bold;")
        else: self.lbl_net.setStyleSheet("color: #f38ba8; font-weight: bold;")

    def send_chat(self):
        msg = self.inp_chat.text().strip()
        if msg and self.client:
            self.client.send_obj({'type': 'chat', 'msg': msg})
            self.on_chat("Вы", msg)
            self.inp_chat.clear()

    def toggle_mic(self):
        if not self.audio_engine: return
        self.audio_engine.mic_muted = not self.audio_engine.mic_muted
        if self.audio_engine.mic_muted:
            self.btn_mic.setText("Микрофон: ВЫКЛ")
            self.btn_mic.setStyleSheet("background-color: #f38ba8;")
        else:
            self.btn_mic.setText("Микрофон: ВКЛ")
            self.btn_mic.setStyleSheet("")

    def toggle_cam(self):
        if not self.video_engine: return
        if self.video_engine.mode == 'camera':
            self.video_engine.set_mode('none')
            self.btn_cam.setText("Камера: ВЫКЛ")
            self.btn_cam.setStyleSheet("")
            self.clear_local_video()
            self.client.send_obj({'type': 'video_stop'})
        else:
            self.video_engine.set_mode('camera')
            self.btn_cam.setText("Камера: ВКЛ")
            self.btn_cam.setStyleSheet("background-color: #a6e3a1; color: #11111b;")
            self.btn_scr.setText("Экран: ВЫКЛ")
            self.btn_scr.setStyleSheet("")

    def toggle_scr(self):
        if not self.video_engine: return
        if self.video_engine.mode == 'screen':
            self.video_engine.set_mode('none')
            self.btn_scr.setText("Экран: ВЫКЛ")
            self.btn_scr.setStyleSheet("")
            self.clear_local_video()
            self.client.send_obj({'type': 'video_stop'})
        else:
            self.video_engine.set_mode('screen')
            self.btn_scr.setText("Экран: ВКЛ")
            self.btn_scr.setStyleSheet("background-color: #a6e3a1; color: #11111b;")
            self.btn_cam.setText("Камера: ВЫКЛ")
            self.btn_cam.setStyleSheet("")

    def toggle_hand(self):
        state = self.btn_hand.isChecked()
        if self.client:
            self.client.send_obj({'type': 'hand', 'state': state})

    def clear_local_video(self):
        if self.client and self.client.client_id in self.video_widgets:
            vw = self.video_widgets[self.client.client_id]
            vw.video_label.clear()
            vw.video_label.setText("Нет видео")

    def on_video_stopped(self, uid):
        if uid in self.video_widgets:
            vw = self.video_widgets[uid]
            vw.video_label.clear()
            vw.video_label.setText("Нет видео")

    def leave_room(self):
        if self.audio_engine: self.audio_engine.stop()
        if self.video_engine: self.video_engine.stop()
        if self.client: self.client.stop()
        if self.server: self.server.stop()
        
        for i in reversed(range(self.video_grid.count())): 
            self.video_grid.itemAt(i).widget().setParent(None)
            
        self.stack.setCurrentIndex(0)

    def closeEvent(self, event):
        self.leave_room()
        event.accept()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', type=str, default='')
    parser.add_argument('--create', action='store_true')
    parser.add_argument('--user', type=str, default='')
    
    args, unknown = parser.parse_known_args()

    app = QApplication(sys.argv)
    window = MainWindow(start_args=args)
    window.show()
    sys.exit(app.exec_())