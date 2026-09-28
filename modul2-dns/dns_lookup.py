#!/usr/bin/env python3
"""Modul 2: DNS-opslag bygget fra bunden over UDP.

Scriptet bygger selv en DNS-forespørgsel som rå bytes (header + spørgsmål), sender den
med en UDP-socket til en resolver, og parser svaret, inklusive DNS' pointer-komprimering
af navne. Der bruges ingen DNS-biblioteker (som dnspython).

Brug:
  python3 dns_lookup.py example.com                 A-record via 8.8.8.8
  python3 dns_lookup.py example.com MX              anden recordtype
  python3 dns_lookup.py network.test -s 127.0.0.53  spørg en anden resolver
  python3 dns_lookup.py example.com -v              vis også de rå bytes
  python3 dns_lookup.py github.com TXT --udp-only   vis det afkortede UDP-svar (TC=1)

Er UDP-svaret afkortet (TC=1), gentages forespørgslen automatisk over TCP.
"""
import argparse
import random
import socket
import struct
import sys
import time

# Recordtyper (QTYPE): tallet, der står i pakken, og det navn, vi viser.
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
QTYPE_NAMES = {number: name for name, number in QTYPES.items()}

# RCODE (de sidste 4 bit af flags): DNS' statuskode for svaret.
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

CLASS_IN = 1            # klasse 1 = internettet
BUFFER_SIZE = 4096      # plads til svaret; almindelige UDP-svar er højst 512 bytes
MAX_POINTER_JUMPS = 10  # værn mod pointer-løkker i ondsindede/ødelagte svar


# --------------------------------------------------------------------------
# Opbygning af forespørgslen
# --------------------------------------------------------------------------

def encode_name(domain: str) -> bytes:
    """'example.com' -> b'\\x07example\\x03com\\x00' (længde-præfikserede labels + nul-byte)."""
    domain = domain.rstrip(".")
    if not domain:
        return b"\x00"  # rod-domænet
    encoded = b""
    for label in domain.split("."):
        raw = label.encode("ascii")
        if not 1 <= len(raw) <= 63:
            raise ValueError(f"ugyldig label '{label}': skal være 1-63 tegn")
        encoded += bytes([len(raw)]) + raw   # ét længde-byte, derefter selve tegnene
    return encoded + b"\x00"                 # nul-byte afslutter navnet


def build_query(domain: str, qtype: int) -> tuple[int, bytes]:
    """Bygger en komplet DNS-forespørgsel. Returnerer (transaktions-ID, pakke)."""
    query_id = random.randint(0, 0xFFFF)   # 2 byte, bruges til at genkende vores svar

    flags = 0x0100   # kun RD (recursion desired) er sat: "find svaret for mig"
    # Header, 12 byte: ID, flags, antal spørgsmål, svar, authority- og additional-records.
    # ! = netværks-byterækkefølge (big-endian), H = 2 byte.
    header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)

    # Spørgsmålssektion: navn + type (2 byte) + klasse (2 byte).
    question = encode_name(domain) + struct.pack("!HH", qtype, CLASS_IN)
    return query_id, header + question


# --------------------------------------------------------------------------
# Parsing af svaret
# --------------------------------------------------------------------------

def read_name(msg: bytes, offset: int) -> tuple[str, int]:
    """Læser et navn fra `offset`. Håndterer pointer-komprimering.

    Returnerer (navn, offset til første byte EFTER navnet i den oprindelige position).
    """
    labels = []
    end = None    # hvor læsningen fortsætter efter navnet (sættes ved første pointer)
    jumps = 0
    while True:
        if offset >= len(msg):
            raise ValueError("navnet løber ud over pakken")
        length = msg[offset]

        if length & 0xC0 == 0xC0:
            # Pointer: de to øverste bit er 11, og de resterende 14 bit er en position i
            # pakken, hvor navnet (eller resten af det) allerede står.
            if offset + 1 >= len(msg):
                raise ValueError("afkortet pointer")
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if end is None:
                end = offset + 2
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise ValueError("for mange pointere (mulig løkke)")
            offset = pointer
            continue
        if length & 0xC0:
            raise ValueError("ugyldig label-type")
        if length == 0:      # nul-byte: navnet er slut
            offset += 1
            break

        offset += 1
        if offset + length > len(msg):
            raise ValueError("label løber ud over pakken")
        labels.append(msg[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    if end is None:
        end = offset
    return ".".join(labels) or ".", end


def format_rdata(msg: bytes, rtype: int, start: int, end: int) -> str:
    """Gør rdata (recordens indhold) læsbar, afhængigt af recordtypen."""
    if rtype == QTYPES["A"]:
        if end - start != 4:
            raise ValueError("A-record skal være 4 bytes")
        return socket.inet_ntoa(msg[start:end])
    if rtype == QTYPES["AAAA"]:
        if end - start != 16:
            raise ValueError("AAAA-record skal være 16 bytes")
        return socket.inet_ntop(socket.AF_INET6, msg[start:end])
    if rtype in (QTYPES["NS"], QTYPES["CNAME"]):
        return read_name(msg, start)[0]
    if rtype == QTYPES["MX"]:
        preference = struct.unpack_from("!H", msg, start)[0]
        exchange = read_name(msg, start + 2)[0]
        return f"{preference} {exchange}"
    if rtype == QTYPES["TXT"]:
        # TXT er en række længde-præfikserede tekststrenge.
        parts = []
        i = start
        while i < end:
            length = msg[i]
            parts.append(msg[i + 1:i + 1 + length].decode("utf-8", errors="replace"))
            i += 1 + length
        return " ".join(f'"{p}"' for p in parts)
    if rtype == QTYPES["SOA"]:
        mname, pos = read_name(msg, start)
        rname, pos = read_name(msg, pos)
        serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", msg, pos)
        return f"{mname} {rname} serial={serial} refresh={refresh} retry={retry} " \
               f"expire={expire} minimum={minimum}"
    return msg[start:end].hex(" ")   # ukendt type: vis rå bytes


def parse_record(msg: bytes, offset: int) -> tuple[dict, int]:
    """Parser én resource record. Returnerer (record, offset efter recorden)."""
    name, offset = read_name(msg, offset)
    # TYPE (2), CLASS (2), TTL (4), RDLENGTH (2) = 10 byte
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", msg, offset)
    offset += 10
    end = offset + rdlength
    if end > len(msg):
        raise ValueError("record løber ud over pakken")
    record = {
        "name": name,
        "type": QTYPE_NAMES.get(rtype, str(rtype)),
        "class": rclass,
        "ttl": ttl,
        "data": format_rdata(msg, rtype, offset, end),
    }
    return record, end


def parse_response(msg: bytes) -> dict:
    """Parser header, spørgsmål og svar-sektion."""
    if len(msg) < 12:
        raise ValueError("svaret er kortere end en DNS-header")
    query_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", msg[:12])

    offset = 12
    for _ in range(qdcount):            # spring spørgsmålene over (de er ekko af vores eget)
        _, offset = read_name(msg, offset)
        offset += 4                     # QTYPE + QCLASS

    answers = []
    for _ in range(ancount):
        record, offset = parse_record(msg, offset)
        answers.append(record)

    return {
        "id": query_id,
        "qr": (flags >> 15) & 1,        # 1 = svar
        "aa": (flags >> 10) & 1,        # authoritative answer
        "tc": (flags >> 9) & 1,         # truncated (svaret er afkortet)
        "rd": (flags >> 8) & 1,         # recursion desired (kopi af vores ønske)
        "ra": (flags >> 7) & 1,         # recursion available (resolveren kan slå op for os)
        "rcode": flags & 0xF,
        "counts": (qdcount, ancount, nscount, arcount),
        "answers": answers,
    }


# --------------------------------------------------------------------------
# Netværk
# --------------------------------------------------------------------------

def send_query(packet: bytes, query_id: int, server: str, port: int,
               timeout: float) -> bytes:
    """Sender forespørgslen via UDP og returnerer det første gyldige svar."""
    # AF_INET = IPv4, SOCK_DGRAM = UDP (ingen forbindelse, ingen handshake).
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(packet, (server, port))
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"intet svar fra {server}:{port} inden for {timeout} s")
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
            except TimeoutError:
                raise TimeoutError(f"intet svar fra {server}:{port} inden for {timeout} s")

            # UDP har ingen forbindelse, så hvem som helst kan sende os en pakke. Vi
            # accepterer kun et svar fra den resolver, vi spurgte, med det ID, vi sendte.
            # (Et forfalsket svar skal gætte ID'et. Det er 16 bit, hvilket er svagt.)
            if addr != (server, port):
                print(f"[!] ignorerer pakke fra uventet afsender {addr[0]}:{addr[1]}",
                      file=sys.stderr)
                continue
            if len(data) < 12 or struct.unpack("!H", data[:2])[0] != query_id:
                print("[!] ignorerer pakke med forkert transaktions-ID", file=sys.stderr)
                continue
            return data


def recv_exact(sock: socket.socket, count: int) -> bytes:
    """Læser præcis `count` bytes. TCP er en byte-strøm, så .recv() kan give færre."""
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("forbindelsen blev lukket, før hele svaret var modtaget")
        data += chunk
    return data


def send_query_tcp(packet: bytes, query_id: int, server: str, port: int,
                   timeout: float) -> bytes:
    """Sender forespørgslen over TCP. Bruges, når et UDP-svar er afkortet (TC=1).

    DNS over TCP bruger samme pakkeformat som over UDP, men med en 2-byte længde
    foran, så modtageren ved, hvor beskeden slutter (TCP har ingen beskedgrænser).
    """
    with socket.create_connection((server, port), timeout=timeout) as sock:
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
        data = recv_exact(sock, length)
    if len(data) < 12 or struct.unpack("!H", data[:2])[0] != query_id:
        raise ValueError("forkert transaktions-ID i TCP-svaret")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="DNS-opslag bygget fra bunden over UDP")
    parser.add_argument("domain", help="domænenavn, fx example.com")
    parser.add_argument("type", nargs="?", default="A", help="recordtype (standard: A)")
    parser.add_argument("-s", "--server", default="8.8.8.8", help="resolverens IP (standard: 8.8.8.8)")
    parser.add_argument("-p", "--port", type=int, default=53, help="resolverens port (standard: 53)")
    parser.add_argument("-t", "--timeout", type=float, default=3.0, help="timeout i sekunder")
    parser.add_argument("-v", "--verbose", action="store_true", help="vis de rå bytes")
    parser.add_argument("--udp-only", action="store_true",
                        help="skift ikke til TCP, hvis svaret er afkortet (TC=1)")
    args = parser.parse_args()

    type_name = args.type.upper()
    if type_name not in QTYPES:
        sys.exit(f"Ukendt recordtype '{args.type}'. Understøttet: {', '.join(QTYPES)}")

    try:
        query_id, packet = build_query(args.domain, QTYPES[type_name])
    except ValueError as error:
        sys.exit(f"Fejl: {error}")

    print(f"Spørger {args.server}:{args.port} om {args.domain} ({type_name})")
    print(f"Transaktions-ID: 0x{query_id:04x}")
    if args.verbose:
        print(f"Forespørgsel ({len(packet)} bytes): {packet.hex(' ')}")

    transport = "UDP"
    try:
        data = send_query(packet, query_id, args.server, args.port, args.timeout)
        if args.verbose:
            print(f"Svar ({len(data)} bytes): {data.hex(' ')}")
        result = parse_response(data)

        if result["tc"] and not args.udp_only:
            # TC=1: svaret var for stort til ét UDP-svar. Resolveren beder os spørge
            # igen over TCP, hvor der ikke er en størrelsesgrænse.
            print("[!] Svaret er afkortet (TC=1). Gentager forespørgslen over TCP.")
            data = send_query_tcp(packet, query_id, args.server, args.port, args.timeout)
            if args.verbose:
                print(f"Svar over TCP ({len(data)} bytes): {data.hex(' ')}")
            result = parse_response(data)
            transport = "TCP"
    except OSError as error:   # inkl. TimeoutError og ConnectionError
        sys.exit(f"Fejl: {error}")
    except (ValueError, struct.error) as error:
        sys.exit(f"Fejl: kunne ikke læse svaret ({error})")

    print(f"Transport: {transport}")
    qd, an, ns, ar = result["counts"]
    print(f"Flags: QR={result['qr']} AA={result['aa']} TC={result['tc']} "
          f"RD={result['rd']} RA={result['ra']}  RCODE={RCODES.get(result['rcode'], result['rcode'])}")
    print(f"Spørgsmål: {qd}  Svar: {an}  Authority: {ns}  Additional: {ar}")
    if result["tc"]:
        print("[!] Svaret er afkortet (TC=1), og TCP-fallback er slået fra (--udp-only).")

    if not result["answers"]:
        print("Ingen svar-records.")
        return 1
    print("Svar:")
    for record in result["answers"]:
        print(f"  {record['name']:<28} TTL {record['ttl']:<6} {record['type']:<6} {record['data']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
