#!/usr/bin/env python3
"""Modul 1: simpel TCP-klient til echo-serveren.

Brug:
  python3 client.py            interaktivt: skriv linjer, tom linje afslutter
  python3 client.py "besked"   sender én besked og afslutter

Den interaktive tilstand holder forbindelsen åben, så den kan ses med
`ss -tnp`, mens klienten stadig er tilsluttet.
"""
import socket
import sys

HOST = "127.0.0.1"   # serverens adresse (loopback)
PORT = 9000          # skal være den samme port som i server.py
BUFFER_SIZE = 1024


def send_and_receive(sock: socket.socket, text: str) -> str:
    # Sockets sender bytes, ikke tekststrenge: encode() før afsendelse.
    sock.sendall(text.encode("utf-8"))
    # .recv() garanterer ikke, at hele beskeden kommer på én gang, men til
    # korte beskeder på loopback er ét kald rigeligt.
    reply = sock.recv(BUFFER_SIZE)
    return reply.decode("utf-8")


def main() -> None:
    # with-konteksten lukker socket'en, selv hvis noget fejler undervejs.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((HOST, PORT))   # her sker TCP's three-way handshake
        except ConnectionRefusedError:
            sys.exit(f"Kunne ikke forbinde til {HOST}:{PORT}. Kører serveren?")
        print(f"Forbundet til {HOST}:{PORT}")

        if len(sys.argv) > 1:
            print("svar:", send_and_receive(sock, " ".join(sys.argv[1:])))
            return

        while True:
            try:
                line = input("> ")
            except (EOFError, KeyboardInterrupt):  # Ctrl+D / Ctrl+C
                print()
                break
            if not line:
                break
            print("svar:", send_and_receive(sock, line))
    # Når with-blokken slutter, kaldes .close(), og TCP-afslutningen (FIN) sendes.


if __name__ == "__main__":
    main()
