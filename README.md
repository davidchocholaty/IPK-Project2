# IPK Projekt 2 - Varianta ZETA: Sniffer paketů
Síťový analyzátor pro zachytávání a filtrování paketů na síťovém rozhraní.

## Autor
David Chocholatý

## Seznam odevzdaných souborů
- Makefile
- manual.pdf
- README.md
- error.c
- error.h
- ipk-sniffer.c
- ipk-sniffer.h
- option.c
- option.h
- packet-print.c
- packet-print.h

## Návod použití

### Předpoklady
- gcc
- tar (Nutné pouze při vytváření archivu)

### Vytvoření projektu
Projekt lze vytrořit pomocí Makefile následujícím příkazem
```console
make
```

### Spuštění snifferu

#### Argumenty

Sniffer lze spustit s následujícími argumenty:

-i rozhraní -> rozhraní, na kterém se bude poslouchat
-p port     -> filtrování paketů na daném rozhraní podle portu
-t/--tcp    -> zobrazení pouze TCP paketů
-u/--udp    -> zobrazení pouze UDP paketů
--icmp      -> zobrazení pouze ICMPv4 a ICMPv6 paketů
--arp       -> zobrazení pouze ARP rámců
-n num      -> počet paketů pro zobrazení

#### Příklad spuštění 

##### Obecný zápis volání programu

```console
./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
```

##### Ukázkové příklady
###### Vytvoření projektu
```console
make
```

###### Filtrování tcp a udp paketů na rozhraní eth0 a zobrazení 5 paketů
```console
./ipk-sniffer -i eth0 --tcp -u -n 5
```

###### Filtrování icmp paketů na rozhraní lo a zobrazení 1 paketu
```console
./ipk-sniffer --interface lo --icmp
```

###### Filtrování paketů na rozhraní eth0 dle portu 443 a zobrazení 1 paketu
```console
./ipk-sniffer -p 443 --interface eth0
```

###### Filtrování arp rámců na rozhraní eth0 a zobrazení 1 paketu
```console
./ipk-sniffer --arp -i eth0
```

###### Spuštění snifferu bez určení rozhraní - výpis aktivních rozhraní
```console
./ipk-sniffer
```

