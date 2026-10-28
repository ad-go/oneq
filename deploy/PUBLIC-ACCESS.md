# Acces public la relay-urile oneq (x și y)

Starea de acum (verificată): relay-urile **x** și **y** ascultă pe `0.0.0.0:8443` (TCP, TLS 1.3 X25519MLKEM768) și pe **UDP 8443, 8444, 8445**
(serviciul STUN), sunt federate între ele prin rețeaua privată (`https://10.1.0.2:8443` / `https://10.1.0.1:8443`) și au certificate semnate de
**CA-ul privat al proiectului** (`deploy/oneq-ca.crt`). Din internet nu se văd încă, pentru că hostul fizic/marginea nu redirecționează aceste porturi.
Ce rămâne de făcut este exclusiv pe gazda care are adresele publice (nu în containere).

## 1. Ce trebuie redirecționat

| Adresă publică | Container | Protocol și port public → port în container | Pentru |
|---|---|---|---|
| 86.120.110.185 (x.example.com) | x, 172.172.0.221 | **TCP 8443** → 8443 | login, registru, relay WebSocket |
| 86.120.110.185 | x | **UDP 8443, 8444, 8445** → aceleași | STUN (adresa publică, tipul de NAT, teste de accesibilitate) |
| 86.120.110.186 (y.example.com) | y, 172.172.0.222 | **TCP 8443** → 8443 | idem |
| 86.120.110.186 | y | **UDP 8443, 8444, 8445** → aceleași | idem |

* Porturile publice trebuie să fie **aceleași numere** ca în container (8443/8444/8445): clientul calculează porturile STUN din portul HTTPS
  al relay-ului, iar relay-ul le anunță clienților exact așa cum le-a legat.
* x și m au aceeași adresă publică (.185), la fel y și n (.186). Pe fiecare adresă merge **un singur** relay pe aceste porturi: x pe .185, y pe .186.
  Containerele m și n sunt doar noduri (nu au nevoie de porturi deschise: își găsesc adresa publică prin STUN).
* Nu intră în conflict cu nimic existent: pe 8443-8445 nu mai ascultă nimic; nodurile de test folosesc UDP 51820.
* Un container **nu** ajunge la adresa publică proprie (verificat: x și m nu ajung la `https://x.example.com`, y și n nu ajung la `https://y.example.com`).
  Nodurile din rețeaua privată folosesc de aceea adresele private `https://10.1.0.1:8443` / `https://10.1.0.2:8443` (certificatele le au în SAN).

## 2. Fragmente gata de aplicat (alegeți ce se potrivește gazdei)

**nftables pe gazda care are adresele publice** (DNAT; adăugați și o regulă `accept` în lanțul `forward` dacă politica e `drop`):

```
table ip oneq_public {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    ip daddr 86.120.110.185 tcp dport 8443 dnat to 172.172.0.221:8443
    ip daddr 86.120.110.185 udp dport 8443-8445 dnat to 172.172.0.221
    ip daddr 86.120.110.186 tcp dport 8443 dnat to 172.172.0.222:8443
    ip daddr 86.120.110.186 udp dport 8443-8445 dnat to 172.172.0.222
  }
}
```

**Docker / Compose** (dacă gazda pornește containerele): pentru x

```
ports:
  - "86.120.110.185:8443:8443/tcp"
  - "86.120.110.185:8443:8443/udp"
  - "86.120.110.185:8444:8444/udp"
  - "86.120.110.185:8445:8445/udp"
```

și pentru y la fel cu `86.120.110.186`.

**Proxy cu modul stream** (dacă marginea e un nginx/HAProxy): TCP 8443 se poate trece **doar ca flux TCP** (`stream { server { listen 86.120.110.185:8443; proxy_pass 172.172.0.221:8443; } }`),
**fără** terminare TLS: certificatul trebuie să rămână cel al relay-ului (clientul cere TLS 1.3 cu X25519MLKEM768 direct cu relay-ul).
UDP: `listen 86.120.110.185:8443 udp; proxy_pass 172.172.0.221:8443;` (și 8444, 8445), cu `proxy_responses 1;`.
Un proxy care păstrează adresa sursă nu e necesar; relay-ul vede adresa publică a clientului doar dacă pachetele nu sunt mascate (cu DNAT simplu o vede corect;
un proxy în modul stream o ascunde, iar testul de accesibilitate și limitarea de rată ar vedea adresa proxy-ului).

Adresele containerelor (172.172.0.221/.222) sunt cele de acum; dacă se schimbă la o repornire, actualizați regulile.

## 3. Cum se conectează un client din internet

* Adresele relay-urilor: `https://x.example.com:8443` și `https://y.example.com:8443` (ambele, pentru failover).
* **CA-ul trebuie importat o dată** (certificatele nu sunt de la o autoritate publică): `deploy/oneq-ca.crt`, amprenta SHA-256
  `87:B8:F1:4B:DB:30:85:19:43:92:CC:12:4C:A4:AA:0B:9E:AD:4E:44:AC:7A:07:6E:EB:0F:FF:2E:DD:1F:8F:B1`.
  - aplicațiile: câmpul „Private CA certificate” din Setări (sau importul unui fișier de setări care îl conține);
  - `oneqclient up --cafile oneq-ca.crt …`, `oneqnode run --cafile /etc/oneq/ca.crt …`.
* Comunitatea de pe x și y se numește `oneq` (subnet 10.10.10.0/24); conturile se creează cu `oneqrelay admin …` sau din pagina de administrare.

## 4. Verificare după ce s-au făcut redirecționările

De pe un calculator din **afara** rețelei (de preferință de pe altă conexiune, nu de pe aceeași rețea cu serverele):

```
deploy/check-public.sh x.example.com 8443 deploy/oneq-ca.crt
deploy/check-public.sh y.example.com 8443 deploy/oneq-ca.crt
```

Scriptul verifică TCP 8443 (certificatul se potrivește cu numele și se validează cu CA-ul), `/v1/health`, și rulează `oneqnode nat-check` (UDP, cele trei porturi).
Rezultat așteptat: `NAT type` = tipul NAT-ului clientului, nu „blocked”. Dacă TCP merge dar `nat-check` spune `blocked`, lipsesc redirecționările UDP.

## 5. Ce nu este activat (decizii pentru operator)

* **Pagina de administrare** (`https://x.example.com:8443/admin/`, `https://y.example.com:8443/admin/`) este **pornită** pe ambele relay-uri, deci se vede din internet imediat ce
  portul 8443 e redirecționat. Protecții: parolă de operator + cod TOTP din aplicația authenticator (obligatoriu), blocare după eșecuri (5 → 60 s, dublu până la 15 min),
  fiecare cod o singură dată, jeton de sesiune de 1 h doar în memoria paginii, CSP strict, fiecare modificare în jurnal cu adresa clientului.
  Opțional `admin_allow = <rețele>` în `relay.conf` o ascunde (404) pentru restul lumii: recomandat dacă administrați doar de la adrese cunoscute.
  Înrolarea: fișierele `x.txt`, `y.txt` (parola și datele pentru aplicație) și `x-qr.png`/`y-qr.png` (codul QR) sunt în `C:/oneq/oneq-admin-2fa` pe PC-ul de administrare;
  după ce ați scanat codul și ați mutat parola într-un manager de parole, ștergeți fișierele. Dacă pierdeți telefonul: codurile de recuperare, sau pe server
  `sudo -u oneqrelay oneqrelay admin-totp --out /var/lib/oneq/relay/admin.totp --force` (cere o nouă înrolare).
* **Certificate:** valabile până la 19.10.2028; CA-ul până în 2036. Cheia CA (`C:/oneq/oneq-ca/ca.key` pe PC-ul de administrare) nu se copiază pe servere.
  Reînnoire: `openssl req` pe relay (cheie nouă) → semnare cu CA-ul → `/etc/oneq/relay.crt` și `systemctl restart oneqrelay`.
* **Certificat public (Let's Encrypt):** certificatele publice sunt la margine, nu în containere, deci relay-ul nu are acces la ele. Dacă vreți clienți fără import de CA,
  un certificat public pentru `x.example.com`/`y.example.com` trebuie emis în container (HTTP-01 sau DNS-01) și pus în `cert =`/`key =` din `relay.conf`.
