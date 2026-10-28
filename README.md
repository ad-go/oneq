# VPN post-cuantic: mesh oneqrelay/oneqnode și punct-la-punct oneqtunel

# Două moduri de lucru

1. **Rețea mesh L2 cu utilizatori și parole (recomandat):** `oneqrelay` (servere federate) + `oneqnode` (noduri L2/TAP), IP/MAC alocate automat. Descrierea completă: [ARCHITECTURE.md](ARCHITECTURE.md). Specificația formală a protocolului de fir (formate, chei, transcript, model de amenințare, ce nu garantează): [specifications.html](specifications.html), verificată cu `spec_check.py`.
2. **Punct-la-punct (`oneqtunel.py`):** un tunel L3 între două noduri cu chei schimbate manual; secțiunile de mai jos.

Instalarea clienților (Windows, macOS, Debian, Android), cu exemple de comenzi: [client/README.md](client/README.md#installing-a-client-examples).

## Pachete Debian (Debian 13, amd64)

Două pachete, `oneqrelay` și `oneqnode`, instalează aplicația în **`/opt/oneq/relay`** și **`/opt/oneq/node`** (bibliotecile Python incluse), cu comenzile legate în `/usr/bin`, și o configurează din fișiere reale:

| Fișier | Rol |
|---|---|
| `/etc/oneq/relay.conf` | configurarea oneqrelay (INI, secțiunea `[relay]`): `id`, `listen`, `db`, `secret_file`, `federation_peers`, `cert`/`key`, `init` |
| `/etc/oneq/node.conf` | configurarea oneqnode: `[defaults]` plus câte o secțiune `[NUME]` per nod (`relays`, `community`, `user`, `key_file`, `password_file`, `advertise`, …) |

Opțiunile din linia de comandă le suprascriu; o opțiune scrisă greșit oprește serviciul cu un mesaj clar. Cheile și parolele nu stau în aceste fișiere, ci în fișiere separate (`/etc/oneq/relay.secret`, `/etc/oneq/node-NUME.key`, `node-NUME.password`, mod 0600), referite prin cale.

```sh
sudo apt install ./oneq-server_0.0.1_all.deb ./oneqnode_0.0.1_amd64.deb ./oneqrelay_0.0.1_amd64.deb    # server: nod + relay (doar nod: ./oneqnode_0.0.1_amd64.deb); sau din depozitul apt (repo/README.md)
sudo oneqrelay-admin community-add lan 10.50.0.0/24
sudo oneqrelay-admin user-add lan alice --role admin
sudo oneqnode-init lan --relay https://r1.example.org --community lan --user alice
```

Serviciile pornesc sub systemd sau supervisord (detectat, sau `init =` în fișierul de configurare). Construire: `packaging/build-debs.sh`; depozit semnat: `packaging/make-repo.sh` + `packaging/sign-repo.sh`; teste: `packaging/{smoke,service,repo}-test.sh`.
Depozitul apt semnat este în Gitea, `ad-go/oneq-apt` (0.0.1, trixie/amd64; cheia `oneq-archive-keyring.gpg`, amprenta `4C33 A0A0 1EC9 798B 53EE 638D 1F87 9861 4F16 22ED`); `oneq.sources` conține un URL substituent (`https://apt.example.org/oneq`) până când directorul e servit de un server web.

## Rețea mesh: pornire rapidă

```sh
# 1. Același secret al federației pe toate oneqrelay-urile
oneqrelay.py gen-secret > federation.secret && chmod 600 federation.secret

# 2. Pe primul oneqrelay: comunitate și utilizatori (parola din fișier / $TUNMESH_PASSWORD / prompt, niciodată din argumente)
oneqrelay.py admin --db r1.db --id r1 --secret-file federation.secret community-add lan 10.50.0.0/24
oneqrelay.py admin --db r1.db --id r1 --secret-file federation.secret user-add lan alice --role admin --password-file alice.pw
oneqrelay.py admin --db r1.db --id r1 --secret-file federation.secret list

# 3. Pornești oneqrelay-urile (TLS 1.3 doar X25519MLKEM768); conturile și nodurile se replică între ele
oneqrelay.py run --id r1 --db r1.db --secret-file federation.secret --listen 0.0.0.0:8443     --cert fullchain.pem --key privkey.pem --fed-peer https://r2.example.org:8443 --cafile ca.pem
oneqrelay.py run --id r2 --db r2.db --secret-file federation.secret ... --fed-peer https://r1.example.org:8443

# 4. Pe fiecare nod: cheie proprie, apoi intri în comunitate (IP și MAC vin de la oneqrelay)
oneqnode.py genkey --key node.key
oneqnode.py run --key node.key --relay https://r1.example.org:8443 --relay https://r2.example.org:8443     --community lan --user alice --password-file alice.pw --name laptop --advertise 203.0.113.5:51820 --listen 0.0.0.0:51820
```

- Mai multe `--relay` = failover automat. Un `oneqnode` rămâne în rețea și când toate oneqrelay-urile cad.
- Administrarea (`oneqrelay.py admin`): `community-add`, `community-subnet`, `user-add`, `user-passwd`, `user-disable`, `user-enable`, `user-del`, `node-del`, `relay-grant`, `relay-revoke`, `route-add`, `route-del`, `list`.
  Schimbarea parolei sau dezactivarea revocă imediat toate token-urile contului, pe toată federația. `community-subnet COMUNITATE 10.10.10.0/24` mută comunitatea pe alt subnet: fiecare nod primește o adresă nouă (MAC-urile, cheile, utilizatorii și rutele rămân)
  și o preia la repornire; se refuză dacă noul subnet e prea mic sau acoperă o rută.
- Legat la adresa unei interfețe existente: `oneqnode.py run ... --via IFACE`. Interfața rămâne a procesului care o ține (nu se partajează); `oneqnode` își face propriul TAP.
- Producție: `deploy/oneqrelay.service`, `deploy/oneqnode@.service`, `deploy/nginx-oneqrelay.conf`, `deploy/oneqnode.env.example`.
- Teste mesh: `test_mesh_core.py`, `test_oneqrelay.py`, `test_oneqnode.py` (fără root), `sudo python3 test_e2e_mesh.py` (TAP reale, 2 oneqrelay + 3 oneqnode în namespace-uri: direct, relay forțat prin federație, fallback + failover + revenire, conturi).

---

## Noduri delegate ca relay

Federația poate **delega noduri obișnuite să facă relay** pentru ceilalți membri, fără să le dea vreun secret. Nodul se oferă (`relay_offer = yes` în `node.conf`, `--relay-offer`),
administratorul îl delegă (pagina de admin: butonul „Delegate…” pe nod, sau `oneqrelay admin relay-grant COMUNITATE NODE [--max-kbps N] [--days D] [--force]`), iar nodurile care nu se
pot atinge direct își trimit pachetele (criptate cap-la-cap) prin el, pe UDP, înainte de a recurge la relay-ul WebSocket al `oneqrelay`. Condiții: nodul trebuie să fie accesibil din
exterior (NAT `open` sau `cone`, măsurat de STUN), iar toate relay-urile federației să cunoască delegările. Revocarea: `relay-revoke` sau „Withdraw”. Detalii: ARCHITECTURE.md.

## Rute printr-un nod gateway

O rețea privată din spatele unui membru (de ex. `192.168.16.0/24`) poate fi făcută accesibilă transparent celorlalți membri. Administratorul o anunță printr-un nod **gateway**:

    oneqrelay admin route-add COMUNITATE 192.168.16.0/24 NOD [--prio 100]      # NOD: id, prefix de id (8+ cifre) sau nume; sau pagina de admin, secțiunea „Routes”
    oneqrelay admin route-del COMUNITATE 192.168.16.0/24 [NOD]                 # un gateway, sau toate

Aceeași rețea poate avea până la 4 gateway-uri (redundanță): clientul folosește cel cu prioritatea cea mai bună dintre cele care răspund și trece la următorul când acela tace, fără să revină singur.
Gatewayul este un nod obișnuit cu `ip_forward` și NAT (`deploy/oneq-gateway`, `deploy/oneq-gateway.service`: doar rețeaua anunțată iese din mesh). Clienții Rust primesc rutele cu `--accept-routes`
(`accept_routes` în configurația serviciului, implicit oprit) și acceptă doar rețele private din afara mesh-ului. Detalii: ARCHITECTURE.md, `client/README.md`.

## Relay pe Windows și macOS

Pachetele pentru Windows și macOS (`client/package-desktop.py`) conțin și nodul, și relay-ul (cu Python 3.13 / OpenSSL 3.5 propriu): `oneqclient relay init`, apoi
`oneqclient relay install` (serviciu Windows `oneqrelay` / daemon launchd), vezi `client/README.md`. Pe Android nu există relay (doar nodul): relay-ul e în Python.
`oneqrelay init --dir DIR --name HOST` face aceeași configurare pe orice mașină fără pachetul Debian.

## Pagina de administrare a oneqrelay

Fiecare oneqrelay poate servi o pagină de administrare pe același port TLS: `https://<relay>/admin/`. Este oprită până setezi
`admin_password_file` în `/etc/oneq/relay.conf` (parola operatorului, fișier mod 0600 al utilizatorului `oneqrelay`). **Al doilea factor
este obligatoriu**: coduri TOTP (RFC 6238) din orice aplicație de tip authenticator (Google/Microsoft Authenticator, Aegis, FreeOTP, 1Password…).
Fără `admin_totp_file` relay-ul refuză să pornească pagina: autentificarea în doi pași e obligatorie, din orice rețea.

    sudo -u oneqrelay oneqrelay gen-admin-password --out /etc/oneq/admin.pw      # scrie fișierul (0600) și afișează parola o dată
    sudo -u oneqrelay oneqrelay admin-totp --out /var/lib/oneq/relay/admin.totp --issuer "oneqrelay x" \
         --save-enrolment /tmp/enrol.txt                                       # QR în terminal, link otpauth, secret, 10 coduri de recuperare
    # în relay.conf:  admin_password_file = /etc/oneq/admin.pw
    #                 admin_totp_file     = /var/lib/oneq/relay/admin.totp
    #                 admin_allow         = 203.0.113.0/24, 10.0.0.0/8      # opțional: ceilalți primesc 404
    # apoi: systemctl restart oneqrelay

Fișierul TOTP stă în `/var/lib/oneq/relay`, nu în `/etc`: serviciul îl rescrie la fiecare login (ultimul pas folosit, codurile de recuperare consumate),
iar systemd montează `/etc` doar-citire pentru el; relay-ul verifică la pornire că îl poate scrie.

Pagina are trei secțiuni:

* **Relay**: setările efective (id, port, transport TLS-PQ, bază de date, CA de federație, configurația), versiune, uptime,
  noduri atașate, totaluri și limitele din această versiune. Setările din fișier se schimbă în `relay.conf` (cu restart).
* **Federație**: peer-ii, vârsta ultimei sincronizări, legăturile de relay active și amprenta secretului federației (aceeași pe
  toate relay-urile). Peer-ii se pot adăuga/scoate din pagină (rămân salvați local); cei din `relay.conf` doar se afișează.
  Replicarea *trage* date de la peer: pentru legătură în ambele sensuri adaugi peer-ul și pe celălalt relay.
* **Comunități**: creare, modificare (MTU, număr maxim de noduri), ștergere în cascadă (cere numele comunității); per comunitate
  utilizatori (adăugare, parolă nouă, activare/dezactivare, rol, cotă de noduri, ștergere) și noduri (adresă, MAC, proprietar,
  stare, relay-ul de care sunt atașate, scoatere). Modificările trec prin registrul replicat, deci ajung pe toate relay-urile.

Autentificare: parolă + cod din aplicație (fereastră de ±30 s pentru ceasuri diferite). Un cod nu poate fi folosit de două ori (nici după repornire:
ultimul pas acceptat e salvat), un cod greșit sau o parolă greșită dau același mesaj și aceeași blocare (5 eșecuri → 60 s, apoi dublu până la 15 min),
codul se consumă doar dacă parola era corectă, iar dacă starea nu poate fi salvată codul e refuzat. Cele 10 coduri de recuperare (hash în fișier) merg o singură dată.
Securitate: jeton de operator semnat HMAC (1 h) ținut doar în memoria paginii (fără cookie), blocare după eșecuri repetate,
CSP strict fără resurse externe, fiecare modificare apare în jurnal cu adresa clientului. Un jeton de utilizator de comunitate
(chiar cu rol `admin`) nu are acces. Parola nu se afișează și nu se stochează în pagină.

## Dovada de posesie a cheii nodului

*English version: [POP.md](POP.md).*

`node_id` este hash-ul cheii publice, iar cheile publice nu sunt secrete (lista de membri le arată). Fără o dovadă, oricine are un token (modul punct-la-punct) sau un cont
(mesh) ar putea înregistra cheia altcuiva cu adrese proprii sau ar putea ocupa `node_id`-ul înainte de proprietar. Cheile nodurilor sunt chei KEM (X25519 + ML-KEM-768), nu chei de
semnătură, deci dovada e o **provocare** pe care o deschide doar deținătorul cheii private (`oneqpop.py`):

1. Nodul cere `POST /v1/c/<comunitate>/nodes/<id>/challenge` (modul punct-la-punct: `POST /v1/nodes/<id>/challenge`) cu cheia publică.
2. Serverul încapsulează ML-KEM către cheia nodului, face un schimb X25519 efemer–static și sigilează un secret `R = HMAC(cheia_serverului, nonce | exp | node_id)`. **Nu ține stare**:
   la federație, `cheia_serverului` e derivată din secretul comun, deci orice relay verifică o provocare făcută de altul.
3. Nodul deschide provocarea și răspunde cu `HMAC(R, "proof" | node_id | nonce | exp)`, trimis în `PUT` ca `pop` (valabil 60 s și reutilizat până aproape de expirare).

Reguli: un nod înregistrat o dată cu dovadă **nu mai poate fi actualizat fără dovadă** (apără și împotriva coborârii în grad); `--require-pop` (`require_pop = yes`) refuză orice
înregistrare fără dovadă; un administrator poate reseta un `node_id` ștergând nodul. În modul punct-la-punct, și slotul de relay WebSocket al unui nod verificat cere dovada
(`X-Oneq-Pop`). Un relay care nu cunoaște provocarea răspunde 404, iar nodul face o înregistrare simplă (compatibilitate). Dovada nu acoperă restul cererii: apără de cine **nu** are cheia, nu de un
atacator care citește fluxul TLS. Clientul Rust și cel Python implementează același protocol. Pachetul `oneqrelay` depinde de `cryptography` (ML-KEM).

## Noduri în spatele NAT

*English version of this section: [NAT.md](NAT.md).*

Orice nod ajunge la oricine prin relay (WebSocket, mereu atașat). Calea directă UDP se obține în plus, dacă NAT-urile permit.

**Ce face `oneqrelay`.** Pornește implicit un serviciu STUN (RFC 5389, cu `CHANGE-REQUEST` pe port ca în RFC 5780) pe **trei porturi UDP**
ale adresei de ascultare: portul `listen`, +1 și +2 (`stun`, `stun_port`, `stun_alt_port`, `stun_change_port` în `relay.conf`; trebuie
deschise în firewall). Poate testa și dacă un nod acceptă pachete nesolicitate: `POST /v1/c/<comunitate>/nodes/<id>/nat-test`
trimite un Binding request dintr-un port pe care nodul nu l-a contactat niciodată (doar către adresa publică a apelantului;
loopback/link-local/multicast sunt refuzate; o probă la 5 s per nod).

**Ce face nodul** (`oneqnode`, clientul Rust, aplicațiile): trei tranzacții STUN de pe același socket UDP cu care face traficul:
1. portul principal → adresa publică M1 (fără răspuns = `blocked`);
2. portul alternativ → M2; M2 ≠ M1 ⇒ maparea depinde de destinație ⇒ `symmetric`;
3. portul principal cu change-port ⇒ răspunsul vine de pe al treilea port, necontactat: dacă ajunge ⇒ `cone`, altfel `port-restricted`
   (adresa locală = M1 ⇒ `open`, fără NAT).
Rezultatul (tip, adresă publică, „inbound”) apare în registru, în pagina de administrare și în aplicații; adresa publică devine
candidat pentru ceilalți (nu la `symmetric`: portul se schimbă cu destinația). Se măsoară din nou la 5 min sau când maparea se schimbă.
`oneqnode nat-check HOST:PORT` arată rezultatul fără să intre în comunitate.

**Care perechi se conectează direct**

| | open | cone | port-restricted | symmetric |
|---|---|---|---|---|
| **open** | direct | direct | direct | direct |
| **cone** | direct | direct | direct | direct |
| **port-restricted** | direct | direct | direct | relay |
| **symmetric** | direct | direct | relay | relay |

Perechile „relay” nu așteaptă 10 s: nodurile știu dinainte că nu se poate și merg imediat pe relay (traficul funcționează la fel).
Tabelul e cel de bază; patru mecanisme îl schimbă (secțiunile de mai jos): maparea unui port pe router, predicția de porturi, al doilea NAT și IPv6.

| Situație | Regulă |
|---|---|
| simetric cu pas de port previzibil (`delta`) față de port-restricted | direct (celălalt capăt sondează porturile prezise) |
| simetric față de simetric, **ambele** cu `delta` | direct |
| o parte cu al doilea NAT (`cgnat`) | relay imediat, în afară de cazul în care celălalt capăt e `open` |
| ambele părți au IPv6 global | se încearcă mereu direct (nu există traducere, doar un firewall cu stare) |
| mapare pe router verificată din exterior | se publică `open` |

**Sincronizarea hole punching-ului.** Între două NAT-uri care filtrează, un pachet care ajunge la un NAT *înainte* ca acel NAT să fi
trimis ceva „otrăvește” tabela de conexiuni (netfilter: maparea următoare trece pe alt port) și retrimiterea o menține vie. De aceea
cele două noduri nu trimit pachete nesolicitate decât în **runde** aliniate la ceasul relay-ului (măsurat la fiecare înregistrare,
eroare ≤ jumătate din RTT): la fiecare 4 s, în primele 3 runde din 10 (liniștea de ~32 s lasă starea eșuată să expire), în rafale de 4
pachete. Când sosește un pachet de la celălalt capăt, „gaura” e folosită imediat (INIT sau probă), către acea adresă și numai către IP-uri
înregistrate de el (o adresă falsificată nu declanșează un handshake de 2 KB spre un terț). Între un nod `open`/`cone` și oricine, se
păstrează încercările continue de dinainte.

**Teste** (`test_nat_sim.py`, ca root pe Linux cu NAT-uri reale simulate: namespace-uri + nftables, 15 ms latență pe fiecare legătură):
clasificarea pentru open, port-restricted (`masquerade`), symmetric (`masquerade random`), cone (SNAT/DNAT static) și UDP blocat;
perechi de noduri: port-restricted ↔ port-restricted (cazul greu), port-restricted ↔ cone, symmetric ↔ cone, open ↔ symmetric
se conectează direct, symmetric ↔ port-restricted merge pe relay imediat; aceleași cazuri între **clientul Rust** (compilat pentru Linux cu Zig)
și nodul Python, în ambele ordini de roluri, plus Rust ↔ Rust. Fără latență (0,1 ms) două NAT-uri Linux se „otrăvesc” reciproc
(artefact de laborator: pe internet latența separă pachetele), de aceea testul cere `tc netem`.

**Deschiderea automată a unui port pe router (PCP, NAT-PMP, UPnP).** Dacă NAT-ul nu e `open`, nodul cere routerului de acasă să
redirecționeze portul UDP al nodului: întâi PCP (RFC 6887, UDP 5351 pe gateway), apoi NAT-PMP (RFC 6886), apoi UPnP IGD (descoperire SSDP,
`AddPortMapping` prin SOAP; `oneqportmap.py` și `client/core/src/portmap.rs`, aceeași logică). Maparea se reînnoiește la jumătatea duratei și
se șterge la oprire. Nodul **nu pretinde** că e deschis pe baza răspunsului routerului: cere relay-ului să sondeze adresa externă a mapării dintr-un
port necontactat (`nat-test`) și abia dacă răspunsul vine publică `open` (cu `via: pcp|natpmp|upnp`); celelalte noduri încearcă atunci adresa direct,
fără hole punching. Un răspuns UPnP se acceptă numai de la o adresă privată/link-local, cu `LOCATION` și URL-ul de control pe aceeași adresă (un
răspuns falsificat nu poate trimite nodul spre un terț), cu corpuri limitate la 64 KB. Oprire: `--no-port-mapping` (`port_mapping = no` în `node.conf`).

**Al doilea NAT (CGNAT, un router în spatele altui router).** Nodul se consideră în spatele a două NAT-uri dacă adresa văzută de relay e în
100.64.0.0/10 (RFC 6598) sau dacă routerul își raportează (NAT-PMP/PCP/UPnP) altă adresă WAN decât cea văzută de relay. O mapare pe primul router
ar fi inutilă (se șterge), nodul publică `cgnat: true`, iar perechea merge **imediat pe relay**, în afară de cazul în care celălalt capăt e `open`. Dacă
routerul nu răspunde la niciun protocol, se vede doar cazul 100.64.0.0/10; un CGNAT cu adrese publice nu poate fi recunoscut așa.

**Predicția de porturi (NAT simetric).** Pentru un NAT simetric nodul face o a treia tranzacție STUN, către portul „change” al relay-ului (anunțat ca
`stun.change_port`): trei mapări consecutive cu pas constant (`delta`, 1..64, sau pași mici pozitivi) ⇒ alocare secvențială. Publică `delta` și cea mai nouă
mapare; celălalt capăt trimite PUNCH și către `port + delta·k`, k = 1..16, în rundele sincronizate. Astfel simetric ↔ port-restricted și
simetric ↔ simetric (ambele cu `delta`) nu mai merg obligatoriu pe relay. Metoda ghicește: dacă NAT-ul a servit alte fluxuri între măsurare și
punching, ținta poate fi ratată (fereastra de 16 porturi acoperă o parte); nu ajută la NAT-uri cu porturi aleatoare, care rămân pe relay.

**IPv6.** Socketul de date al nodului e dual-stack (`::` cu `IPV6_V6ONLY` oprit; înapoi la IPv4 dacă sistemul nu poate). O adresă IPv6 globală
(2000::/3, aleasă de sistem pentru internet, fără să se trimită vreun pachet) se publică ca `[adresa]:port`, iar candidații IPv6 ai celorlalți se
încearcă la fel ca cei IPv4. Două noduri cu IPv6 global nu trec prin regulile NAT (nu există traducere, doar un firewall cu stare) și nu cad pe relay din
motive de NAT. `--no-ipv6` (`ipv6 = no`) le oprește.

`oneqnode nat-check` arată și pasul alocării de porturi și dacă există un al doilea NAT. Un `--advertise` verificat de relay: dacă nu răspunde la
sondă, nodul scrie un avertisment.


# Modul 2: punct-la-punct (oneqtunel)

Proiect educațional, **fără audit criptografic independent**.

- **Handshake:** X25519 + ML-KEM-768 (secretul ML-KEM înaintea celui X25519 în fiecare KDF), 2 mesaje:
  `INIT` 2329 B, `RESP` 2225 B, fragmentate la nivel de aplicație (≤ 1200 B/datagramă).
- **Date:** ChaCha20-Poly1305, contor pe 64 de biți, fereastră anti-replay de 1024. Rekey la 120 s, respingere la 180 s, keepalive la 25 s.
- **Descoperire:** API HTTPS de întâlnire (`rendezvous_server.py`), TLS 1.3 **doar** X25519MLKEM768, fără fallback.
- **Relay:** dacă după ~10 s nu există sesiune directă, datagramele merg opace printr-un WebSocket (`wss://…/v1/relay`). Tunelul revine singur pe calea directă (probă la 20 s).
- `LABEL`: `tunsec-pq/v1 …` (constanta de fir a modului punct-la-punct). Orice schimbare de protocol primește o versiune nouă.

## Cerințe

Python legat de **OpenSSL ≥ 3.5** (`python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"`), `/dev/net/tun`, `ip`.

```sh
python3 -m venv /opt/oneq-src/venv && /opt/oneq-src/venv/bin/pip install -r requirements.txt
/opt/oneq-src/venv/bin/python -c "from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey"
```

## Chei și schimbul cheilor publice

```sh
oneqtunel.py genkey --key A.key          # scrie A.key (0600) și A.key.pub (1216 B, base64); afișează node_id
```

Schimbi **fișierele `.pub`** între cele două noduri printr-un canal de încredere. Serverul de întâlnire nu e de încredere pentru identitate, pentru că handshake-ul autentifică nodurile după cheile statice. `node_id = SHA-256(cheie publică)[:16]`. Nodul cu cheia publică mai mică e inițiatorul.

## Token și server

```sh
python3 -c "import secrets;print(secrets.token_urlsafe(32))" > net.token && chmod 600 net.token   # același pe ambele noduri
python3 rendezvous_server.py hash-token < net.token >> /etc/oneq-p2p/tokens.sha256                   # serverul ține doar hash-ul
```

Server cu TLS direct (certificat propriu sau Let's Encrypt):

```sh
rendezvous_server.py run --listen 0.0.0.0:8443 --cert fullchain.pem --key privkey.pem --tokens-file tokens.sha256
```

În producție e recomandat în spatele nginx/Caddy (`deploy/`), cu serverul pe `127.0.0.1:8080 --insecure-http --trust-proxy`.

## Pornirea unui nod

```sh
# token din fișier (0600) sau din mediu (TUNSEC_TOKEN). Niciodată din linia de comandă.
oneqtunel.py run --key A.key --peer B.key.pub --ifname pq0 --addr 10.99.0.1/24 \
   --listen 0.0.0.0:51820 --advertise 203.0.113.5:51820 \
   --rendezvous https://rv.example.org --token-file net.token [--cafile ca.pem] [--stun host:3478]
```

Necesită `CAP_NET_ADMIN` (sau un TUN persistent: `ip tuntap add dev pq0 mode tun user oneq-p2p`, apoi `--no-config`, caz în care nodul nu mai are nevoie de privilegii).
Fără rendezvous (test sau IP-uri fixe): `--peer-endpoint IP:PORT`. Relay: `--force-relay`, `--no-relay`, `--relay-after SEC`.

## Legarea la o interfață (`--via`)

`--via IFACE` leagă socketul UDP la adresa interfeței IFACE (de exemplu a unui alt tunel existent). Adresa ei e anunțată ca un candidat în plus. Interfața e **ținută de procesul care a creat-o și nu poate fi partajată**: tunelul își creează **propria** interfață TUN (`--ifname pq0`), iar traficul circulă încapsulat prin cealaltă interfață. MTU-ul implicit în acest caz este **1220** (1380 altfel). Se poate suprascrie cu `--mtu`.

## Verificarea TLS post-cuantic

Cu un `openssl` ≥ 3.5:

```sh
openssl s_client -connect rv.example.org:443 -tls1_3 -groups X25519MLKEM768 -brief </dev/null   # trebuie: "Negotiated TLS1.3 group: X25519MLKEM768"
openssl s_client -connect rv.example.org:443 -tls1_3 -groups X25519          -brief </dev/null   # trebuie să eșueze (handshake_failure)
```

**Mecanismul:** Python 3.13 nu are `SSLContext.set_groups`, așa că `pqtls.py` setează `OPENSSL_CONF=pq_openssl.cnf` (TLS 1.3, `Groups = X25519MLKEM768`) *înainte* de `import ssl`. Fișierul se încarcă doar în procesele noastre, nu și în restul sistemului. Clientul (`Rendezvous`, `RelayClient`) refuză orice server care nu oferă acest grup. Pe proxy, restricția se impune cu `ssl_ecdh_curve X25519MLKEM768` (nginx) sau `curves x25519mlkem768` (Caddy).

## Producție

`deploy/`: `oneq-p2p@.service` (utilizator `oneq-p2p`, `CAP_NET_ADMIN` doar aici, cheia și tokenul prin `LoadCredential`), `oneq-p2p-rendezvous.service` (fără capabilități), `nginx-rendezvous.conf`, `Caddyfile`, `node.env.example`.

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin oneq-p2p;  useradd --system ... oneq-p2p-rv
install -m600 A.key /etc/oneq-p2p/NAME.key;  install -m600 net.token /etc/oneq-p2p/NAME.token
cp deploy/node.env.example /etc/oneq-p2p/NAME.env && chmod 600 /etc/oneq-p2p/NAME.env   # editezi ONEQ_P2P_ARGS
systemctl enable --now oneq-p2p@NAME
```

## Teste

```sh
python3 test_oneqtunel.py        # unitare + TLS (openssl s_client) + API + relay + fragmentare, fără root
python3 test_nginx_proxy.py      # nginx real (OpenSSL ≥ 3.5) în fața serverului
sudo python3 test_e2e.py         # 2 TUN reale în namespace-uri: direct, relay forțat, fallback + revenire; fără text în clar pe fir
```

## Depanare

| Simptom | Cauză probabilă |
|---|---|
| `handshake failure` către rendezvous | serverul/proxy-ul nu oferă X25519MLKEM768 (OpenSSL < 3.5) |
| `pqtls must be imported before ssl` | un modul importă `ssl` înainte de `pqtls` |
| `cannot import mlkem` | `cryptography` prea vechi (cere ≥ 50.0.2 testat) |
| fără sesiune, fără relay | token greșit (401), ceasuri decalate > 180 s (INIT respins), UDP blocat și `--no-relay` |
| sesiune doar prin relay | NAT simetric sau firewall; verifică `--advertise` și porturile UDP |
| `private key must not be accessible…` | `chmod 600` pe cheie/token |
| TUN: `Operation not permitted` | lipsește `CAP_NET_ADMIN` (sau TUN persistent cu `--no-config`) |
| MTU/pierderi cu `--via` (încapsulare în alt tunel) | folosește `--mtu 1220` sau mai mic |

## Limite cunoscute

- **Dovada de posesie a cheii nodului** (vezi secțiunea de mai jos, [POP.md](POP.md) în engleză): rezolvă ocuparea unui `node_id` de către un deținător de token/cont care
  nu are cheia privată. Nu apără de un relay compromis (care poate șterge un nod și aloca adresa lui altei chei) și nici de un deținător al contului care are și cheia. Fără
  `--require-pop`, un nod care nu dă dovadă este acceptat și poate fi ocupat.
- Un singur peer per nod (modul punct-la-punct); pentru mai mulți peeri se folosește modul mesh.
- Predicția de porturi ghicește (vezi „Noduri în spatele NAT”); un NAT cu porturi aleatoare, un CGNAT cu adrese publice și un NAT simetric fără pas constant rămân pe relay.

## Update check

The relay, the Python node and the clients look once a day on the GitHub Releases of `ad-go/oneq` whether a newer version exists
(`GET https://api.github.com/repos/ad-go/oneq/releases/latest`, HTTPS only, no identifiers, no telemetry; drafts and pre-releases are ignored).
When one exists, the relay admin page shows a one-line banner and the node writes one log line. The package can be downloaded from the admin
page (`oneqnode update-download` on a node) and is verified against the `SHA256SUMS` of the same release; a file that does not match is deleted.
Nothing is ever installed or executed automatically: you install the downloaded package yourself.
Turn the automatic check off with `update_check = no` in `relay.conf` / `node.conf` (the "Check for updates" button and
`oneqnode update-check` keep working). `update_url` overrides the release API address, `update_dir` the download directory of the relay.
