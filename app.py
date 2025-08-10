import os
import subprocess
import shlex
import uuid
import json
import sqlite3
import sys
import webbrowser
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO
import signal

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*")

DB_FILE = 'scans.db'
INSTALL_SCRIPT = 'install_advanced.sh'

active_processes = {}

project_dir = os.path.dirname(os.path.abspath(__file__))
seclists_wordlist_path = os.path.join(project_dir, "SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt")

ALLOWED_TOOLS = {
    "Nmap": {
        "command": "nmap -v {scan_type} {target} -oX -",
        "user_inputs": [
            {"name": "target", "placeholder": "ej: 192.168.1.1 o example.com", "required": True},
            {"name": "scan_type", "placeholder": "-T4 -A -v", "required": True}
        ],
        "topology_parser": True
    },
    "Nikto": {
        "command": "nikto -h {target}",
        "user_inputs": [
            {"name": "target", "placeholder": "ej: http://example.com", "required": True}
        ]
    },
    "Gobuster": {
        "command": "gobuster dir -u {target} -w {wordlist} -t 50",
        "user_inputs": [
            {"name": "target", "placeholder": "ej: https://example.com", "required": True},
            {"name": "wordlist", "placeholder": seclists_wordlist_path, "required": True}
        ]
    },
    "WhatWeb": {
        "command": "whatweb -v {target}",
        "user_inputs": [
            {"name": "target", "placeholder": "ej: example.com", "required": True}
        ]
    },
    "Sublist3r": {
        "command": "sublist3r -d {target}",
        "user_inputs": [
            {"name": "target", "placeholder": "ej: example.com", "required": True}
        ]
    }
}

def run_installation_script():
    print(f"[*] Verificando el entorno y el script de instalación: {INSTALL_SCRIPT}")
    if not os.path.exists(INSTALL_SCRIPT):
        print(f"[-] Error Crítico: El script de instalación '{INSTALL_SCRIPT}' no se encontró.")
        sys.exit(1)
    if not os.access(INSTALL_SCRIPT, os.X_OK):
        print(f"[*] Otorgando permisos de ejecución a {INSTALL_SCRIPT}...")
        os.chmod(INSTALL_SCRIPT, 0o755)
    print("[*] Ejecutando el script de instalación...")
    print("-" * 60)
    try:
        result = subprocess.run(['sudo', './' + INSTALL_SCRIPT], check=False)
        print("-" * 60)
        if result.returncode != 0:
            print(f"[-] El script de instalación falló con el código de salida {result.returncode}.")
            sys.exit(1)
        print("[+] El script de instalación/verificación se completó con éxito.")
        return True
    except Exception as e:
        print(f"[-] Ocurrió una excepción inesperada al ejecutar el script: {e}")
        sys.exit(1)

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                tool TEXT NOT NULL,
                target_info TEXT NOT NULL,
                status TEXT NOT NULL,
                output TEXT
            )
        ''')
        conn.commit()
def run_scan_and_stream(scan_id, tool, command_params):
    command_template = ALLOWED_TOOLS[tool]["command"]
    try:
        safe_params = {k: shlex.quote(v) for k, v in command_params.items()}
        command = command_template.format(**safe_params)
    except KeyError as e:
        socketio.emit('scan_error', {'scan_id': scan_id, 'error': f"Parámetro faltante: {e}"})
        return
    
    with sqlite3.connect(DB_FILE) as conn:
        conn.cursor().execute("UPDATE scans SET status = ? WHERE id = ?", ('running', scan_id))
        conn.commit()

    process = None
    try:
        process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, preexec_fn=os.setsid)
        active_processes[scan_id] = process
        
        full_output = ""
        for line in iter(process.stdout.readline, ''):
            full_output += line
            socketio.emit('scan_update', {'scan_id': scan_id, 'output': line})
            socketio.sleep(0.01)
            
        process.stdout.close()
        return_code = process.wait()
        
        if scan_id in active_processes:
            final_status = 'completed' if return_code == 0 else 'error'
        else:
            final_status = 'stopped'
            
    except Exception as e:
        full_output = f"Error: {e}"
        final_status = 'error'
        socketio.emit('scan_error', {'scan_id': scan_id, 'error': full_output})
    finally:
        if scan_id in active_processes:
            del active_processes[scan_id]

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE scans SET status = ?, output = ? WHERE id = ?", (final_status, full_output, scan_id))
        conn.commit()
        
    socketio.emit('scan_finished', {'scan_id': scan_id, 'status': final_status})



def parse_nmap_xml(xml_string):

    if not xml_string:
        return None
        
    nodes, edges = [], []
    try:
        xml_start = xml_string.find('<?xml')
        if xml_start == -1: return None
        xml_data = xml_string[xml_start:]
        
        root = ET.fromstring(xml_data)
        
        main_target_node = {"id": "target", "label": "Objetivo", "group": "target"}
        nodes.append(main_target_node)

        for host in root.findall('host'):
            status = host.find('status').get('state')
            if status != 'up': continue

            address_element = host.find("address[@addrtype='ipv4']")
            if address_element is None: continue
            address = address_element.get('addr')
            
            host_id = address
            nodes.append({"id": host_id, "label": address, "group": "host", "title": f"IP: {address}"})
            edges.append({"from": "target", "to": host_id})

            ports = host.find('ports')
            if ports:
                for port in ports.findall('port'):
                    if port.find('state').get('state') == 'open':
                        port_id_num = port.get('portid')
                        protocol = port.get('protocol')
                        port_id = f"{address}:{port_id_num}"
                        service = port.find('service')
                        service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                        label = f"{port_id_num}/{protocol}"
                        title = f"Puerto: {port_id_num}\nServicio: {service_name}"
                        nodes.append({"id": port_id, "label": label, "group": "port", "title": title})
                        edges.append({"from": host_id, "to": port_id})
        return {"nodes": nodes, "edges": edges}
    except ET.ParseError as e:
        print(f"Error al parsear XML de Nmap: {e}")
        return None

@app.route('/')
def index(): 
    return render_template('index.html', tools_data=ALLOWED_TOOLS)

@app.route('/api/tools')
def get_tools(): 
    return jsonify(ALLOWED_TOOLS)

@app.route('/api/scans')
def get_past_scans():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT id, tool, target_info, status FROM scans ORDER BY id DESC LIMIT 10")
        return jsonify([dict(row) for row in cursor.fetchall()])

@app.route('/api/scan/details/<scan_id>')
def get_scan_details(scan_id):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = cursor.fetchone()
        if not scan:
            return jsonify({"error": "Scan no encontrado"}), 404
        
        scan_dict = dict(scan)
        
        if ALLOWED_TOOLS.get(scan_dict['tool'], {}).get('topology_parser'):
            
            scan_output = scan_dict.get('output')
            if scan_output: 
                scan_dict['topology'] = parse_nmap_xml(scan_output)
            else:
                scan_dict['topology'] = None 
            
        return jsonify(scan_dict)

@socketio.on('connect')
def handle_connect(): print('[+] Cliente conectado.')

@socketio.on('start_scan')
def handle_start_scan(data):
    tool, params = data.get('tool'), data.get('params', {})
    scan_id = str(uuid.uuid4())
    target_info = json.dumps({'target': params.get('target', 'N/A')})
    
    with sqlite3.connect(DB_FILE) as conn:
        conn.cursor().execute("INSERT INTO scans (id, tool, target_info, status) VALUES (?, ?, ?, ?)", (scan_id, tool, target_info, 'pending'))
        conn.commit()

    socketio.emit('scan_started', {'scan_id': scan_id, 'tool': tool, 'target': params.get('target')})
    socketio.start_background_task(run_scan_and_stream, scan_id, tool, params)

@socketio.on('stop_scan')
def handle_stop_scan(data):
    scan_id = data.get('scan_id')
    print(f"[*] Solicitud para detener el escaneo: {scan_id}")
    if scan_id in active_processes:
        process = active_processes.pop(scan_id)
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            print(f"[+] Proceso {process.pid} para el escaneo {scan_id} ha sido terminado.")
            socketio.emit('scan_stopped', {'scan_id': scan_id, 'message': 'El escaneo ha sido detenido por el usuario.'})
            
            with sqlite3.connect(DB_FILE) as conn:
                conn.cursor().execute("UPDATE scans SET status = ? WHERE id = ?", ('stopped', scan_id))
                conn.commit()

        except ProcessLookupError:
            print(f"[-] El proceso para el escaneo {scan_id} ya no existía.")
        except Exception as e:
            print(f"[-] Error al detener el proceso para {scan_id}: {e}")
            socketio.emit('scan_error', {'scan_id': scan_id, 'error': f'Error al detener el escaneo: {e}'})
    else:
        print(f"[-] No se encontró un proceso activo para el escaneo {scan_id}.")

if __name__ == '__main__':
    run_installation_script()
    init_db()
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        webbrowser.open_new_tab("http://127.0.0.1:5000")
    print("[+] Entorno verificado. Iniciando Vigilantor en http://127.0.0.1:5000")
    socketio.run(app, debug=True, host='0.0.0.0', allow_unsafe_werkzeug=True)
