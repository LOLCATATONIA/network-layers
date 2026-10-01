# Netværks-lag

Byg og forstå din egen netværks-stack fra bunden: DNS, TCP, HTTP og HTTPS i en
IT-sikkerhedskontekst. Hvert modul bygger videre på det forrige, fra rå TCP-sockets til en
HTTPS-sikret webserver, med egen implementering af protokollerne i stedet for færdige
biblioteker.

**[Læs rapporten](https://lolcatatonia.github.io/network-layers/)**

## Struktur

| Mappe | Indhold | Status |
|---|---|---|
| `report/` | Rapporten (kildefiler + byggescript til `index.html`) | I gang |
| `modul1-tcp/` | TCP echo-server og -klient (modul 1) | Færdig |
| `modul2-dns/` | DNS-opslagsscript bygget fra bunden over UDP (modul 2) | Færdig |
| `modul3-http/` | HTTP-server bygget oven på TCP-koden (modul 3) | **TODO** |
| `modul4-tls/` | TLS/HTTPS tilføjet til HTTP-serveren (modul 4) | **TODO** |
| `modul5-integration/` | Hele kæden samlet: DNS → TCP → TLS → HTTP (modul 5) | **TODO** |

## Miljø

Opgaven er løst direkte på en Linux-vært (CachyOS) i stedet for i en virtuel maskine, da al
trafik i opgaven forbliver på loopback-interfacet. Afvigelser fra opgavens VM-forudsætning er
dokumenteret i rapportens indledende afsnit.
