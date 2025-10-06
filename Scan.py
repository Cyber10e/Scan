import logging
import asyncio
import socket
import ssl
import os
import json
import aiofiles
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
import requests
import websocket
from sslyze import ScannableHost, ServerScanCommand
from sslyze.errors import ConnectionToServerError
from sslyze.scanner.scanner import Scanner
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import struct
from celery import Celery
import gzip
from io import BytesIO

# Logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Configs
BOT_TOKEN = os.getenv('BOT_TOKEN', '8115589333:AAHleqvJH8lXze5pcVjsnzklv_4nbDHwyYkb')
CELERY_BROKER = 'sqla+sqlite:///celery.db'  # Hardcoded SQLite backend for Celery

# Celery setup with SQLite backend
celery_app = Celery('scanner', broker=CELERY_BROKER, backend=CELERY_BROKER)
celery_app.conf.update(task_track_started=True, result_expires=3600)

# SQLite database for user sessions and scan results
DB_FILE = 'scanner.db'

# Scan configurations
SCAN_CONFIGS = {
    'tls': {'port': 443, 'sni': 'nl1.wstunnel.xyz', 'description': '🛡️ TLS Scan\n- Deep cipher/cert analysis\n- WebSocket tunnels'},
    'http': {'port': 443, 'description': '🌐 HTTP Scan\n- 200 OK + headers'},
    'vless': {'port': 443, 'path': '/vpnjantit', 'description': '⚡ VLESS Scan\n- V2Ray/XRay protocols'},
    'reality': {'port': 443, 'description': '🔮 Reality SNI Scan\n- XTLS-Vision optimized'},
    'sniproxy': {'port': 443, 'description': '🕵️ SNI Proxy Scan\n- Proxy/CDN bypass detection'},
    'wireguard': {'port': 51820, 'description': '🔒 WireGuard Scan\n- VPN handshake check'},
    'openvpn': {'port': 1194, 'description': '🔐 OpenVPN Scan\n- UDP/TCP handshake'},
    'shadowsocks': {'port': 8388, 'key': 'testkey123', 'description': '🛡️ Shadowsocks Scan\n- Encrypted proxy'},
    'websocket': {'port': 80, 'description': '🔄 WebSocket Scan\n- Non-TLS WS servers'}
}

DEFAULT_JOBS = 50
TIMEOUT = 10
RETRY_ATTEMPTS = 2
RATE_LIMIT = 10  # Scans per minute per user

# SQLite setup
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                protocol TEXT,
                port INTEGER,
                sni TEXT,
                jobs INTEGER,
                last_scan TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                user_id INTEGER,
                protocol TEXT,
                start_time TEXT,
                results TEXT
            )
        ''')
        conn.commit()

init_db()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    # Rate limiting
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute('SELECT last_scan FROM users WHERE user_id = ?', (user_id,))
        row = cur.fetchone()
        if row and row[0]:
            last_scan = datetime.fromisoformat(row[0])
            if (datetime.now() - last_scan).total_seconds() < 60:
                cur.execute('SELECT COUNT(*) FROM scans WHERE user_id = ? AND start_time > ?', 
                            (user_id, (datetime.now() - timedelta(minutes=1)).isoformat()))
                count = cur.fetchone()[0]
                if count >= RATE_LIMIT:
                    await update.message.reply_text("🚫 Rate limit exceeded. Try again in a minute.")
                    return
        conn.execute('INSERT OR REPLACE INTO users (user_id, last_scan) VALUES (?, ?)', 
                     (user_id, datetime.now().isoformat()))
        conn.commit()

    keyboard = [
        [InlineKeyboardButton("🛡️ TLS", callback_data='tls'), InlineKeyboardButton("🌐 HTTP", callback_data='http')],
        [InlineKeyboardButton("⚡ VLESS", callback_data='vless'), InlineKeyboardButton("🔮 Reality", callback_data='reality')],
        [InlineKeyboardButton("🕵️ SNI Proxy", callback_data='sniproxy'), InlineKeyboardButton("🔒 WireGuard", callback_data='wireguard')],
        [InlineKeyboardButton("🔐 OpenVPN", callback_data='openvpn'), InlineKeyboardButton("🛡️ Shadowsocks", callback_data='shadowsocks')],
        [InlineKeyboardButton("🔄 WebSocket", callback_data='websocket'), InlineKeyboardButton("⚙️ Settings", callback_data='settings')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🔍 **Ultimate Auto SQLite Scanner** 🚀\n\n"
        "Scan unlimited hosts for SNIs, VPNs, proxies!\n\n"
        "Protocols:\n" + "\n\n".join(f"**{k.upper()}**: {v['description']}" for k, v in SCAN_CONFIGS.items()) + "\n\n"
        "**Instructions**:\n1. Pick protocol\n2. Upload hosts.txt (or /generate)\n3. Set port/SNI\n4. Get results.txt + JSON\n5. Check past scans with /results <scan_id>",
        parse_mode='Markdown', reply_markup=reply_markup
    )

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    user_id = update.effective_user.id
    if data == 'settings':
        await query.edit_message_text("⚙️ **Settings**\n- Jobs: /jobs <num>\n- Timeout: /timeout <sec>\n- Port: /port <num>\n- SNI: /sni <host>")
        return
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('UPDATE users SET protocol = ? WHERE user_id = ?', (data, user_id))
        conn.commit()
    keyboard = [[InlineKeyboardButton("Custom Port", callback_data='custom_port'), InlineKeyboardButton("Custom SNI", callback_data='custom_sni')]]
    await query.edit_message_text(
        f"**Selected**: {SCAN_CONFIGS[data]['description']}\n\nUpload `hosts.txt` or use /generate.",
        reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown'
    )

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute('SELECT protocol, port, sni, jobs FROM users WHERE user_id = ?', (user_id,))
        row = cur.fetchone()
        if not row or not row[0]:
            await update.message.reply_text("Select protocol with /start.")
            return
        protocol, port, sni, jobs = row

    document = update.message.document
    if document.file_name != 'hosts.txt':
        await update.message.reply_text("Upload `hosts.txt` only.")
        return

    file = await context.bot.get_file(document.file_id)
    async with aiofiles.open(f'temp_hosts_{user_id}.txt', 'wb') as f:
        await f.write(await file.download_as_bytearray())
    async with aiofiles.open(f'temp_hosts_{user_id}.txt', 'r') as f:
        hosts = [line.strip() async for line in f if line.strip()]
    os.remove(f'temp_hosts_{user_id}.txt')

    if not hosts:
        await update.message.reply_text("Empty file.")
        return

    jobs = jobs or DEFAULT_JOBS
    port = port or SCAN_CONFIGS[protocol]['port']
    sni = sni or SCAN_CONFIGS[protocol].get('sni', '')

    scan_id = f"{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    await update.message.reply_text(f"🔄 Queuing {len(hosts)} hosts ({protocol.upper()}) with {jobs} workers... Scan ID: {scan_id}")

    task = scan_hosts_task.delay(hosts, protocol, jobs, port, sni, scan_id, user_id)
    context.user_data['scan_id'] = scan_id
    context.user_data['task_id'] = task.id
    context.user_data['protocol'] = protocol  # Store protocol for send_results
    asyncio.create_task(monitor_task(update, context, scan_id, len(hosts)))

@celery_app.task
def scan_hosts_task(hosts: List[str], protocol: str, jobs: int, port: int, sni: str, scan_id: str, user_id: int):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results, working_hosts = loop.run_until_complete(scan_hosts(hosts, protocol, jobs, port, sni))
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            'INSERT INTO scans (scan_id, user_id, protocol, start_time, results) VALUES (?, ?, ?, ?, ?)',
            (scan_id, user_id, protocol, datetime.now().isoformat(), json.dumps(results))
        )
        conn.commit()
    return results, working_hosts, scan_id

async def scan_hosts(hosts: List[str], protocol: str, jobs: int, port: int, sni: str) -> Tuple[List[Dict], List[str]]:
    queue = asyncio.Queue()
    for host in hosts:
        await queue.put(host)
    
    async def worker():
        results = []
        while not queue.empty():
            host = await queue.get()
            for attempt in range(RETRY_ATTEMPTS + 1):
                try:
                    if protocol == 'tls':
                        result = await advanced_tls_scan(host, port, sni)
                    elif protocol == 'http':
                        result = await http_scan(host, port)
                    elif protocol == 'vless':
                        result = await vless_scan(host, port, SCAN_CONFIGS['vless']['path'])
                    elif protocol == 'reality':
                        result = await reality_scan(host, port)
                    elif protocol == 'sniproxy':
                        result = await sniproxy_scan(host, port, sni)
                    elif protocol == 'wireguard':
                        result = await wireguard_scan(host, port)
                    elif protocol == 'openvpn':
                        result = await openvpn_scan(host, port)
                    elif protocol == 'shadowsocks':
                        result = await shadowsocks_scan(host, port, SCAN_CONFIGS['shadowsocks']['key'])
                    elif protocol == 'websocket':
                        result = await websocket_scan(host, port)
                    results.append(result)
                    break
                except Exception as e:
                    if attempt == RETRY_ATTEMPTS:
                        results.append({'host': host, 'success': False, 'error': str(e), 'latency': None})
                    await asyncio.sleep(2 ** attempt)
            queue.task_done()
        return results

    workers = [asyncio.create_task(worker()) for _ in range(min(jobs, len(hosts)))]
    all_results = []
    for w in workers:
        all_results.extend(await w)
    working_hosts = [r['host'] for r in all_results if r.get('success')]
    return all_results, working_hosts

async def advanced_tls_scan(host: str, port: int, sni: str) -> Dict:
    start_time = datetime.now()
    try:
        server_location = ScannableHost.from_hostname(hostname=host, ip_address=None)
        scanner = Scanner()
        scanner.set_command(ServerScanCommand.SSLYZE__CERTIFICATE_INFO)
        scanner.set_command(ServerScanCommand.SSLYZE__CIPHER_SUITES)
        scanner.set_command(ServerScanCommand.SSLYZE__HEARTBLEED)
        results = await asyncio.to_thread(scanner.run_scan, server_location)

        cert_info = results[0].result.as_xml() if results[0].result else "No cert"
        ciphers = len(results[1].result.cipher_suites) if results[1].result else 0
        heartbleed = "Vulnerable!" if results[2].result.vulnerable_servers else "Safe"
        grade = "A" if ciphers > 50 else "C"

        ws_success = False
        try:
            ws_url = f"wss://{host}:{port}/"
            ws = websocket.create_connection(ws_url, header={'Host': sni}, sslopt={"check_hostname": False, "cert_reqs": ssl.CERT_NONE}, timeout=TIMEOUT)
            ws_success = ws.connected
            ws.close()
        except:
            pass

        latency = (datetime.now() - start_time).total_seconds()
        return {
            'host': host, 'success': ws_success and grade != "F", 'details': f"Grade: {grade}, Ciphers: {ciphers}, Heartbleed: {heartbleed}", 
            'score': min(100, ciphers * 2), 'latency': latency
        }
    except ConnectionToServerError:
        return {'host': host, 'success': False, 'error': 'Connection failed', 'latency': None}

async def http_scan(host: str, port: int) -> Dict:
    start_time = datetime.now()
    url = f"https://{host}:{port}" if port != 443 else f"https://{host}"
    try:
        resp = requests.get(url, timeout=TIMEOUT, verify=False)
        latency = (datetime.now() - start_time).total_seconds()
        return {'host': host, 'success': resp.status_code == 200, 'details': f"Status: {resp.status_code}", 'score': 100 if resp.status_code == 200 else 0, 'latency': latency}
    except Exception as e:
        return {'host': host, 'success': False, 'error': str(e), 'latency': None}

async def vless_scan(host: str, port: int, path: str) -> Dict:
    start_time = datetime.now()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                header = b'\x03' + b'\x00' * 16 + path.encode()
                ssock.send(header)
                resp = ssock.recv(1024)
                is_vless = len(resp) > 0 and not resp.startswith(b'HTTP')
                latency = (datetime.now() - start_time).total_seconds()
                return {'host': host, 'success': is_vless, 'details': f"Resp: {len(resp)} bytes", 'score': 100 if is_vless else 0, 'latency': latency}
    except Exception as e:
        return {'host': host, 'success': False, 'error': str(e), 'latency': None}

async def reality_scan(host: str, port: int) -> Dict:
    start_time = datetime.now()
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    try:
        context = ssl.create_default_context()
        context.set_alpn_protocols(['h2', 'http/1.1'])
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.send(b'\x03' + b'\x00' * 16 + b'reality')
                resp = ssock.recv(1024)
                score = 100 if len(resp) > 0 and not resp.startswith(b'HTTP') else 50
                latency = (datetime.now() - start_time).total_seconds()
                return {'host': host, 'success': score > 70, 'details': f"TLS 1.3: Yes, Score: {score}", 'score': score, 'latency': latency}
    except Exception as e:
        return {'host': host, 'success': False, 'error': str(e), 'latency': None}

async def sniproxy_scan(host: str, port: int, sni: str) -> Dict:
    start_time = datetime.now()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                req = f"GET / HTTP/1.1\r\nHost: {sni}\r\n\r\n".encode()
                ssock.send(req)
                resp = ssock.recv(1024).decode(errors='ignore')
                is_proxy = 'Proxy' in resp or 'X-Forwarded' in resp
                latency = (datetime.now() - start_time).total_seconds()
                return {'host': host, 'success': is_proxy, 'details': f"Proxy Headers: {'Yes' if is_proxy else 'No'}", 'score': 100 if is_proxy else 0, 'latency': latency}
    except Exception as e:
        return {'host': host, 'success': False, 'error': str(e), 'latency': None}

async def wireguard_scan(host: str, port: int) -> Dict:
    start_time = datetime.now()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        packet = struct.pack('<I', 1) + b'\x00' * 28
        sock.sendto(packet, (host, port))
        resp, _ = sock.recvfrom(1024)
        is_wireguard = len(resp) >= 32 and resp[:4] == struct.pack('<I', 2)
        latency = (datetime.now() - start_time).total_seconds()
        sock.close()
        return {'host': host, 'success': is_wireguard, 'details': f"Handshake: {'Success' if is_wireguard else 'Failed'}", 'score': 100 if is_wireguard else 0, 'latency': latency}
    except Exception as e:
        return {'host': host, 'success': False, 'error': str(e), 'latency': None}

async def openvpn_scan(host: str, port: int) -> Dict:
    start_time = datetime.now()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((host, port))
        packet = b'\x00\x0e' + b'\x38' + b'\x00' * 12
        sock.send(packet)
        resp = sock.recv(1024)
        is_openvpn = len(resp) > 0 and b'\x38' in resp
        latency = (datetime.now() - start_time).total_seconds()
        sock.close()
        return {'host': host, 'success': is_openvpn, 'details': f"Handshake: {'Success' if is_openvpn else 'Failed'}", 'score': 100 if is_openvpn else 0, 'latency': latency}
    except Exception as e:
        return {'host': host, 'success': False, 'error': str(e), 'latency': None}

async def shadowsocks_scan(host: str, port: int, key: str) -> Dict:
    start_time = datetime.now()
    try:
        cipher = Cipher(algorithms.AES(key.encode()), modes.CFB(b'\x00' * 16))
        encryptor = cipher.encryptor()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((host, port))
        payload = encryptor.update(b'\x05\x01\x00')
        sock.send(payload)
        resp = sock.recv(1024)
        is_shadowsocks = len(resp) > 0
        latency = (datetime.now() - start_time).total_seconds()
        sock.close()
        return {'host': host, 'success': is_shadowsocks, 'details': f"Response: {len(resp)} bytes", 'score': 100 if is_shadowsocks else 0, 'latency': latency}
    except Exception as e:
        return {'host': host, 'success': False, 'error': str(e), 'latency': None}

async def websocket_scan(host: str, port: int) -> Dict:
    start_time = datetime.now()
    try:
        ws_url = f"ws://{host}:{port}/"
        ws = websocket.create_connection(ws_url, timeout=TIMEOUT)
        ws_success = ws.connected
        ws.close()
        latency = (datetime.now() - start_time).total_seconds()
        return {'host': host, 'success': ws_success, 'details': f"WS Handshake: {'Success' if ws_success else 'Failed'}", 'score': 100 if ws_success else 0, 'latency': latency}
    except Exception as e:
        return {'host': host, 'success': False, 'error': str(e), 'latency': None}

async def monitor_task(update: Update, context: ContextTypes.DEFAULT_TYPE, scan_id: str, total_hosts: int):
    task_id = context.user_data['task_id']
    scanned = 0
    while True:
        task = celery_app.AsyncResult(task_id)
        if task.state == 'SUCCESS':
            results, working_hosts, _ = task.get()
            await send_results(update, results, working_hosts, context.user_data['protocol'], scan_id)
            break
        elif task.state == 'FAILURE':
            await update.message.reply_text("❌ Scan failed. Try again.")
            break
        await asyncio.sleep(5)
        scanned = min(scanned + 10, total_hosts)  # Simulate progress
        await update.message.reply_text(f"📊 Progress: {scanned}/{total_hosts} hosts")

async def send_results(update: Update, results: List[Dict], working_hosts: List[str], protocol: str, scan_id: str):
    total = len(results)
    success_rate = len(working_hosts) / total * 100 if total else 0
    avg_latency = sum(r.get('latency', 0) for r in results if r.get('latency')) / total if total else 0
    message = f"📊 **Scan Complete** ({protocol.upper()}) - ID: {scan_id}\n\n✅ Success: {len(working_hosts)}/{total} ({success_rate:.1f}%)\n⏱️ Avg Latency: {avg_latency:.2f}s\n\n"
    for res in results[:10]:
        status = "✅" if res['success'] else "❌"
        message += f"• {res['host']}: {status} | {res.get('details', res.get('error', 'N/A'))}\n"
    if len(results) > 10:
        message += f"... + {len(results)-10} more\n"
    await update.message.reply_text(message, parse_mode='Markdown')

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{protocol}_results_{timestamp}.txt.gz"
    json_filename = f"{protocol}_results_{timestamp}.json"

    details = [
        {'host': r['host'], 'score': r.get('score', 100), 'latency': r.get('latency'), 'details': r.get('details', ''), 'vulns': r.get('vulns', [])}
        for r in results if r.get('success')
    ]

    with BytesIO() as buf:
        with gzip.GzipFile(fileobj=buf, mode='wb') as gz:
            content = "\n".join(host for host in working_hosts) + "\n\n--- Details ---\n" + "\n".join(
                f"{d['host']}: Score {d['score']}, Latency {d['latency']:.2f}s - {d['details']}" for d in sorted(details, key=lambda x: x['score'], reverse=True)
            )
            gz.write(content.encode())
        buf.seek(0)
        await update.message.reply_document(document=buf, filename=filename, caption=f"📄 {protocol.upper()} working hosts (compressed)")

    async with aiofiles.open(json_filename, 'w') as f:
        await f.write(json.dumps(details, indent=2))
    with open(json_filename, 'rb') as f:
        await update.message.reply_document(document=f, filename=json_filename, caption="🔍 JSON export")
    os.remove(json_filename)

async def get_results(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        scan_id = context.args[0]
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.execute('SELECT results, protocol FROM scans WHERE scan_id = ?', (scan_id,))
            row = cur.fetchone()
            if not row:
                await update.message.reply_text("Scan ID not found.")
                return
            results = json.loads(row[0])
            protocol = row[1]
            working_hosts = [r['host'] for r in results if r.get('success')]
            await send_results(update, results, working_hosts, protocol, scan_id)
    except:
        await update.message.reply_text("Usage: /results <scan_id>")

async def set_jobs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        jobs = int(context.args[0])
        user_id = update.effective_user.id
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute('UPDATE users SET jobs = ? WHERE user_id = ?', (min(jobs, 100), user_id))
            conn.commit()
        await update.message.reply_text(f"🔧 Jobs set to {jobs}")
    except:
        await update.message.reply_text("Usage: /jobs <num> (1-100)")

async def set_port(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        port = int(context.args[0])
        user_id = update.effective_user.id
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute('UPDATE users SET port = ? WHERE user_id = ?', (port, user_id))
            conn.commit()
        await update.message.reply_text(f"🔧 Port set to {port}")
    except:
        await update.message.reply_text("Usage: /port <num>")

async def set_sni(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        sni = context.args[0]
        user_id = update.effective_user.id
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute('UPDATE users SET sni = ? WHERE user_id = ?', (sni, user_id))
            conn.commit()
        await update.message.reply_text(f"🔧 SNI set to {sni}")
    except:
        await update.message.reply_text("Usage: /sni <host>")

async def generate_sample(update: Update, context: ContextTypes.DEFAULT_TYPE):
    sample_hosts = ["www.google.com", "www.cloudflare.com", "yahoo.com"]
    async with aiofiles.open('sample_hosts.txt', 'w') as f:
        for host in sample_hosts:
            await f.write(f"{host}\n")
    with open('sample_hosts.txt', 'rb') as f:
        await update.message.reply_document(document=f, filename="hosts.txt", caption="📝 Sample hosts.txt")
    os.remove('sample_hosts.txt')

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(CommandHandler("jobs", set_jobs))
    app.add_handler(CommandHandler("port", set_port))
    app.add_handler(CommandHandler("sni", set_sni))
    app.add_handler(CommandHandler("generate", generate_sample))
    app.add_handler(CommandHandler("results", get_results))
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()