#!/usr/bin/env python3
"""
Uso:
    python3 bt_peer.py server <porta>
    python3 bt_peer.py client <ip> <porta> [--plain]
    python3 bt_peer.py dht <ip> <porta>
"""
import socket
import sys

TIMEOUT = 4
PSTR = b"BitTorrent protocol"
INFO_HASH = bytes(range(20))
PEER_ID = b"-PY0001-" + b"0" * 12


def handshake():
    return bytes([len(PSTR)]) + PSTR + (b"\x00" * 8) + INFO_HASH + PEER_ID


def dht_query():
    tid = b"aa"
    return (
        b"d1:ad2:id20:" + PEER_ID + b"e"
        b"1:q4:ping"
        b"1:t2:" + tid
        + b"1:y1:qe"
    )


def cmd_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    print(f"[server] escutando em :{port} (loop)", flush=True)
    while True:
        conn, addr = s.accept()
        conn.settimeout(TIMEOUT)
        try:
            data = conn.recv(256)
            print(f"[server] conexao de {addr}, {len(data)} bytes recebidos:", flush=True)
            print(f"[server] {data!r}", flush=True)
        except socket.timeout:
            print(f"[server] conexao de {addr} aceita, mas nenhum dado chegou (timeout)", flush=True)
        finally:
            conn.close()


def cmd_client(ip, port, plain):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    payload = b"HELLO nao-BT so texto normal\n" if plain else handshake()
    tipo = "PLAIN (nao-BT)" if plain else "BitTorrent handshake"
    print(f"[client] conectando em {ip}:{port} para enviar {tipo} ({len(payload)} bytes)")
    try:
        s.connect((ip, port))
        s.sendall(payload)
        print("[client] enviado, aguardando resposta/echo...")
        try:
            data = s.recv(256)
            print(f"[client] {len(data)} bytes de volta: {data!r}")
        except socket.timeout:
            print("[client] conectou e enviou, mas sem resposta (timeout)")
        print("[client] RESULTADO: CONECTOU (nao foi bloqueado)")
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"[client] RESULTADO: BLOQUEADO / FALHOU ({type(e).__name__}: {e})")
    finally:
        s.close()


def cmd_dht(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    payload = dht_query()
    print(f"[dht] enviando consulta DHT ({len(payload)} bytes) para {ip}:{port}/udp")
    try:
        s.sendto(payload, (ip, port))
        try:
            data, addr = s.recvfrom(256)
            print(f"[dht] resposta de {addr}: {data!r}")
        except socket.timeout:
            print("[dht] enviado, sem resposta (timeout)")
        print("[dht] RESULTADO: pacote SAIU sem erro de socket")
    except OSError as e:
        print(f"[dht] RESULTADO: FALHOU ao enviar ({type(e).__name__}: {e})")
    finally:
        s.close()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "server" and len(sys.argv) == 3:
        cmd_server(int(sys.argv[2]))
    elif cmd == "client" and len(sys.argv) in (4, 5):
        plain = len(sys.argv) == 5 and sys.argv[4] == "--plain"
        cmd_client(sys.argv[2], int(sys.argv[3]), plain)
    elif cmd == "dht" and len(sys.argv) == 4:
        cmd_dht(sys.argv[2], int(sys.argv[3]))
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
