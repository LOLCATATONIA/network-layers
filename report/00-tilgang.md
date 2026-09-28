---
title: "Netværks-lag"
subtitle: "Byg og forstå din egen netværks-stack fra bunden:  \nDNS, TCP, HTTP og HTTPS i en IT-sikkerhedskontekst"
author: "Alexander Mangaard"
date: "28. september 2026"
---

# Overordnet tilgang og metodevalg

## Miljø: CachyOS direkte i stedet for en Linux-VM

Opgavebeskrivelsen forudsætter en Linux-VM fra Linux Basics-forløbet. Jeg arbejder i stedet direkte
på min CachyOS-maskine, som allerede er et Linux-system. Al trafik i opgaven forbliver på
loopback-interfacet (`127.0.0.1`), så en VM ville ikke give andre protokoller eller andre
capture-resultater.

*(Afsnittet udbygges med konkrete afvigelser fra opgaven, efterhånden som de opstår.)*

## Repo-struktur

```
Netværkslag/
├── report/                (denne rapport: kildefiler + byggescript)
├── modul1-tcp/            (kildekode)
├── modul2-dns/
├── modul3-http/
├── modul4-tls/
└── modul5-integration/
```
