#!/usr/bin/env python3
"""Modul 1: simpel TCP echo-server.

Serveren lytter på loopback, accepterer én klient ad gangen og sender
alt, den modtager, tilbage uændret ("echo").
"""
import socket

# Bind kun til loopback: serveren er ikke tilgængelig fra andre maskiner.
# 0.0.0.0 ville betyde "alle netværksinterfaces" og eksponere tjenesten unødigt.
HOST = "127.0.0.1"
PORT = 9000          # 8080 er reserveret til HTTP-serveren i modul 3
BUFFER_SIZE = 1024   # antal bytes pr. .recv()-kald


def handle_client(conn: socket.socket, addr: tuple) -> None:
    """Ekko'er data tilbage, indtil klienten lukker forbindelsen."""
    print(f"[+] Forbindelse fra {addr[0]}:{addr[1]}")
    with conn:
        while True:
            data = conn.recv(BUFFER_SIZE)
            # .recv() returnerer tom bytes (b''), når klienten har lukket sin
            # side af forbindelsen (den har sendt FIN). Så er vi færdige.
            if not data:
                break
            # Sockets arbejder med bytes; decode() kun for at kunne vise teksten.
            print(f"    modtog: {data.decode('utf-8', errors='replace')!r}")
            conn.sendall(data)  # sendall() sender alle bytes, ikke kun en del
    print(f"[-] Forbindelse lukket: {addr[0]}:{addr[1]}")


def main() -> None:
    # AF_INET = IPv4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        # Tillad genbrug af porten straks efter en genstart. Uden denne
        # mislykkes .bind() med "Address already in use", mens den gamle
        # forbindelse står i TIME_WAIT.
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        print(f"Lytter på {HOST}:{PORT} (Ctrl+C afslutter)")
        try:
            while True:
                # .accept() blokerer, indtil en klient forbinder, og returnerer
                # et nyt socket-objekt til netop den forbindelse.
                conn, addr = server.accept()
                handle_client(conn, addr)
        except KeyboardInterrupt:
            print("\nServeren stoppes.")


if __name__ == "__main__":
    main()
