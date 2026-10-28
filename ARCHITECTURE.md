# Arhitectura rețelei mesh (oneqrelay + oneqnode)

Proiect educațional, **fără audit criptografic independent**.

Rețeaua este o rețea Ethernet virtuală (L2, TAP) formată din noduri (`oneqnode`), plus servere de întâlnire și relay (`oneqrelay`) care se federează între ele. Are **utilizatori cu parolă**, **alocare automată de IP/MAC** și un schimb de chei **post-cuantic** (X25519 + ML-KEM-768).

```
          federație (TLS 1.3, X25519MLKEM768, HMAC cu secretul federației)
   oneqrelay r1 <=====================================> oneqrelay r2
      ^   ^  login, înregistrare, lista membrilor, relay (wss)   ^
      |   +------------------+                                   |
   oneqnode A <---- UDP direct, sesiune end-to-end (PQ) ----> oneqnode B ---- oneqnode C
```

## Roluri

| Componentă | Rol |
|---|---|
| `oneqrelay` | Registru de comunități, conturi, noduri și adrese; relay WebSocket; federație cu alte oneqrelay-uri. Nu vede traficul. |
| `oneqnode` | Se autentifică, primește IP/MAC, deschide sesiuni cu toți membrii, comută cadre Ethernet între TAP și sesiuni. |
| `meshproto.py` | Protocolul de fir `tunmesh-pq/v2`: handshake, date, indexuri. |
| `meshdb.py` | Stocarea replicată (SQLite), conturile, token-urile, alocarea de adrese. |

Planul de date merge direct între noduri (UDP, cu hole punching) sau, dacă nu se poate, prin relay. **Dacă toate oneqrelay-urile cad, sesiunile existente continuă**: doar descoperirea și intrarea de noi membri au nevoie de ele.

## Modelul de încredere

- **oneqrelay-urile sunt de încredere pentru *apartenență***: cine poate intra în comunitate și ce adresă primește. Nu sunt de încredere pentru confidențialitate: nu văd și nu pot decripta traficul.
- `node_id = SHA-256(cheie publică)[:16]`, iar nodurile verifică ele însele această legătură pentru fiecare intrare din registru. Un oneqrelay compromis poate **adăuga** membri, dar nu poate înlocui cheia unui nod existent (ar schimba `node_id`-ul).
- Handshake-ul autentifică ambele capete prin chei statice (X25519 + ML-KEM), nu prin parolă. **Parola nu e cheie de criptare**: deschide accesul la registru și la relay. De aceea poate fi schimbată sau revocată fără să atingă sesiunile.
- Autentificarea între oneqrelay-uri folosește un secret comun al federației (HMAC peste metodă, cale, corp și timp, fereastră de 60 s), peste TLS cu verificarea certificatului.

## Conturi și autentificare

- Fiecare **comunitate** are subrețea, MTU, limită de noduri și utilizatori (`user` sau `admin`, cota de noduri per utilizator).
- Parolele se stochează ca **scrypt** (N=2^15, sare per utilizator) și se replică între oneqrelay-uri. Minimum 8 caractere.
- `POST /v1/login` returnează un **token semnat** (HMAC cu secretul federației, 1 h), valid pe orice oneqrelay. Tokenul conține un contor `tokgen`. La schimbarea parolei, dezactivare sau ștergere, `tokgen` crește (sau contul dispare), iar toate tokenele emise devin invalide, **pe toată federația**, imediat ce modificarea se replică. Rolul nu se citește din token, ci din cont.
- Protecție la atac: limită de rată, blocare după 5 eșecuri pe adresă și pe cont, cu timp dublat la fiecare blocare (60 s … 15 min), verificare de parolă „falsă” pentru conturi inexistente (răspuns la fel de lent).
- Un nod aparține utilizatorului care l-a înregistrat. Un alt utilizator (non-admin) nu poate prelua `node_id`-ul și nu poate atașa relay pentru el.

## Alocarea automată de adrese

- IP: din subrețeaua comunității, ales determinist din `SHA-256(node_id)` cu probare liniară peste adresele luate. **Sticky**: nodul își păstrează adresa cât timp înregistrarea există.
- MAC: `02:` + 5 octeți din `SHA-256(node_id)` (administrat local, unicast), cu salt dacă există coliziune.
- Două oneqrelay-uri pot aloca aceeași adresă simultan (partiție sau cursă). După replicare, înregistrarea cu cel mai mic `(alloc_ts, node_id)` păstrează adresa, iar cea pierzătoare este realocată de oneqrelay-ul care a scris-o (sau de oricare după 30 s). Nodul preia adresa nouă la următoarea reînnoire.
- Subnetul unei comunități se poate schimba (`oneqrelay admin community-subnet COMUNITATE SUBNET`): fiecare nod primește o adresă nouă în el (cu aceeași regulă, nodurile mai vechi primele), MAC-urile, cheile și rutele rămân,
  iar nodurile preiau adresa când se înregistrează din nou (la repornire). Se refuză dacă noul subnet e prea mic pentru noduri sau acoperă o rută.

## Replicarea și federația

- Stocare: înregistrări `(kind, key) -> JSON` cu **ceas logic hibrid**; câștigă `(ts, origin)` mai mare (**last writer wins**). Ștergerile sunt pietre de mormânt. Prezența (puncte finale, atașarea la relay) are TTL de 90 s.
- Tipuri: `comm` (comunitate), `user`, `node`, `pres` (puncte finale), `rel` (la ce oneqrelay e atașat relay-ul nodului).
- **Anti-entropy** pe cursor per peer, peste contorul local de modificări `lseq` (nu pe un vector de versiuni): funcționează pe mai multe salturi, în orice ordine, fără pierderi. Un `epoch` detectează un peer cu baza ștearsă, iar cursorul se resetează. Un `poke` după fiecare modificare declanșează sincronizarea imediată; în rest, o dată la 5 s.
- **Relay între oneqrelay-uri:** dacă destinația e atașată la alt oneqrelay (din `rel`), cadrul trece printr-o legătură WebSocket între cele două (un singur salt, fără bucle).
- **Failover:** `oneqnode` primește o listă de oneqrelay-uri; la eroare trece la următorul, își reface tokenul și reconectează relay-ul.

## Planul de date (L2)

- Fiecare nod ține sesiuni cu toți membrii (mesh complet; rețele mici). Inițiator: nodul cu cheia publică mai mică.
- **Comutare:** unicast către un MAC cunoscut merge la un singur peer; broadcast, multicast și unicast necunoscut se trimit la toți. MAC-urile înregistrate sunt statice; MAC-urile din spatele unui nod (bridge) se învață din cadrele primite și expiră după 5 min. Un membru nu poate folosi MAC-ul altui membru (cadrul se aruncă). Nu există tranzit: un cadru primit de la un peer nu se retransmite altuia, deci nu apar bucle.
- **Căi:** direct (UDP) preferat. Fiecare nod rămâne **atașat tot timpul** la un oneqrelay (WebSocket), ca să poată fi atins prin relay oricând; altfel un peer care trimite prin relay către un nod cu care are sesiune directă ar pierde pachetele. Handshake-ul trece și prin relay pentru un peer fără sesiune directă după 10 s, iar datele trec prin relay când calea directă devine inactivă (75 s fără pachete). Pe relay, o probă la 20 s încearcă calea directă și se revine singură.

## Protocolul de fir `tunmesh-pq/v2`

Mesajele (specificația formală: [specifications.html](specifications.html)):

| Mesaj | Format | Rol |
|---|---|---|
| INIT `0x21` (2349 B) | `tip, idx_i(4), node_id_i(16), E_i, ek_e, ct_sr, AEAD(ts)` | răspunzătorul alege cheia peer-ului din registru după `node_id`, fără încercări de decriptare; antetul intră în transcript |
| RESP `0x22` (2233 B) | `tip, idx_r(4), idx_i(4), E_r, ct_e, ct_si, AEAD("")` | indexuri pentru demultiplexare |
| DATA `0x23` | `tip, receiver_idx(4), contor(8), ChaCha20-Poly1305` | un socket servește multe sesiuni; antetul de 13 B e AAD |

Parametri comuni: ordinea secretelor (ML-KEM înaintea X25519), fragmentarea la 1200 B (`0x15`), fereastra anti-replay de 1024, rekey la 120 s, respingere la 180 s, keepalive la 25 s. **PUNCH `0x14`** (17 B: tip + `node_id`) se trimite la 1 s cât un nod nu are sesiune cu un peer: deschide NAT-ul și, dacă peer-ul e inițiatorul și crede că are o sesiune stabilită, îl face să refacă imediat handshake-ul (limită: o dată la 5 s per peer, doar pentru sesiuni mai vechi de 3 s); fără el, un nod care nu poate iniția (cheia lui e ultima) ar rămâne inaccesibil până la reînnoirea sesiunii. Cadrele Ethernet au cel puțin 14 B, deci sarcinile de 1 octet (`0x00` probă, `0x01` răspuns) nu se pot confunda cu un cadru.

## TLS post-cuantic

API-ul clienților, relay-ul și federația rulează pe TLS 1.3 cu **doar** X25519MLKEM768, prin `OPENSSL_CONF` dedicat (`pq_openssl.cnf`, setat de `pqtls.py` înainte de `import ssl`) sau printr-un reverse proxy cu aceeași restricție (`deploy/nginx-oneqrelay.conf`). Certificatele Let's Encrypt sunt clasice: doar schimbul de chei e post-cuantic.

## Limite cunoscute

- Mesh complet (n² sesiuni): gândit pentru zeci de noduri, nu mii.
- Nu există confirmare de membru de către un admin (orice cont valid cu cotă își poate adăuga noduri).
- Replicarea e „eventual consistent”: după o modificare, o schimbare de parolă sau o revocare poate dura câteva secunde pe alt oneqrelay (token-urile deja verificate acolo rămân valide până la sincronizare).
- Bazele SQLite nu sunt criptate; fișierul conține hash-urile parolelor.

## Pagina de administrare (oneqadmin)

`oneqadmin.py` + `oneqadmin.html` sunt încărcate de `oneqrelay` doar dacă există `admin_password_file`. Rutele `/admin/` (pagina) și
`/admin/api/*` (JSON) folosesc un jeton de operator separat de jetoanele de comunitate (alt prefix HMAC, alt format), deci un
cont `admin` dintr-o comunitate nu poate administra relay-ul. Operațiile scriu în același registru replicat (`meshdb.Registry`:
`users`, `update_community`, `delete_community` în cascadă, `update_user`), iar peer-ii adăugați din pagină se păstrează în
tabela `meta` locală (`fed_extra`, nereplicată: topologia federației rămâne decizia fiecărui operator). Limitatorul de rată al
paginii este separat de cel al API-ului clienților (cheie per adresă și plafon), ca să nu se influențeze.

## Rute printr-un nod gateway

Un administrator poate anunța o rețea privată (de ex. `192.168.16.0/24`) ca accesibilă printr-un membru, **gatewayul**: `oneqrelay admin route-add oneq 192.168.16.0/24 m`, API-ul `PUT /v1/c/<comm>/routes/192.168.16.0_24`
`{"via": "<node id>"}` sau secțiunea „Routes” din pagina de administrare. Registrul păstrează înregistrări `route` (`<comm>/<rețea>_<prefix>` → `{cidr, via, by}`), replicate ca toate celelalte; lista de membri (`GET /nodes`) le include ca `routes`.
O rută dispare odată cu nodul gateway. Reguli: IPv4, prefix cel puțin /8, nu se suprapune subnetului comunității, nu loopback/multicast/link-local, cel mult 64 pe comunitate.

Clientul Rust cu `--accept-routes` (implicit oprit) acceptă doar rețele **private** (RFC 1918 și 100.64/10) din afara mesh-ului, indiferent ce anunță relay-ul: un relay are încredere pentru apartenență, nu pentru a-ți direcționa traficul.
`l3.rs` trimite pachetul IP către MAC-ul gatewayului (cea mai lungă potrivire de prefix; pachetul rămâne neschimbat, doar cadrul are alt MAC), iar `routes_os.rs` pune ruta în sistem pe interfața TUN (`netsh` / `ip` / `route`) și o scoate când
e retrasă sau când nodul se oprește. Răspunsurile vin ca pachete obișnuite către adresa noastră din mesh. Gatewayul este un nod obișnuit cu `ip_forward` și NAT (`deploy/oneq-gateway`): fără NAT, gazdele din rețea nu știu să răspundă către 10.78.0.0/24.
Scriptul permite doar rețeaua anunțată (`FORWARD ... DROP` pentru restul) și corectează MSS-ul (MTU-ul mesh-ului e mai mic).

**Redundanță.** Aceeași rețea poate fi anunțată prin până la 4 gateway-uri (`route-add ... --prio N`, mai mic = preferat; câte o înregistrare `route` pe pereche rețea + gateway, cheia `<comm>/<rețea>_<prefix>/<id nod>`).
Clientul alege, pentru fiecare rețea, gateway-ul cu prioritatea cea mai bună **dintre cele care răspund** (`l3.rs`: sesiune stabilită și un pachet primit în ultimele 45 s; nu prezența din registru, care expiră abia în 90 s),
rămâne pe el cât timp răspunde (fără revenire automată la cel preferat, ca să nu mute conexiunile care trec prin NAT-ul lui) și trece la următorul când tace; dacă nu răspunde niciunul, încearcă mai departe pe cel preferat.
Ruta din sistem (`routes_os.rs`) arată spre gateway-ul preferat (next hop-ul nu contează: adaptorul L3 pune MAC-ul după adresa destinație); starea arată gateway-ul preferat și rezervele.
Limite: un gateway viu în mesh dar fără ieșire spre rețea nu e detectat, nu există împărțire a încărcării, pe Android rețelele se adaugă interfeței VpnService (se reconstruiește când lista se schimbă), nodurile Python TAP nu instalează rute, un client Rust nu poate fi gateway.

## Noduri delegate ca relay (L1)

Un membru al unei comunități poate fi **delegat de un administrator să retransmită pachetele celorlalți membri** când aceștia nu se pot atinge direct
(NAT simetric, UDP blocat între ei). Nodul delegat nu primește niciun secret (nici secretul federației, nici parole) și nu vede traficul: retransmite pachete deja
criptate cap-la-cap.

* **Registru:** tipul de înregistrare `dlg` (`<comunitate>/<node id>` → `{by, max_kbps, exp}`), replicat ca toate celelalte; revocarea e o piatră de mormânt.
  Nodul trebuie să se fi oferit (`relay_offer = yes` → câmpul `offer` din înregistrarea lui) iar acordarea cere ca testul NAT să-l arate accesibil din exterior
  (`open` sau `cone`), în afară de `force`. Lista membrilor are `offer`, `relay_role` (cota în kbit/s, doar dacă oferta e în vigoare și delegarea n-a expirat) și `relays`
  (nodurile delegate cu care membrul are sesiune, publicate la fiecare înregistrare). API: `GET/PUT/DELETE /v1/c/<comm>/relays[/<nid>]` (scrierea doar pentru administratori),
  pagina de admin (butonul „Delegate…” pe nod), `oneqrelay admin relay-grant|relay-revoke`. Un relay ignoră tipurile de înregistrări pe care nu le cunoaște (`dlg`, `route`): actualizează toată federația înainte de a folosi o funcție nouă.
* **Planul de date:** pachet nou `M_RLY = 0x24`, cu antetul, cheile și contorul sesiunii obișnuite (autentificat prin același AEAD); conținutul e o operație între un membru și
  nodul delegat: `FWD dst(16)|datagramă`, `DLV src(16)|datagramă`, `NACK dst(16)|motiv`. Autentificarea membrului față de nodul delegat este chiar sesiunea
  hibridă X25519 + ML-KEM dintre ei (nodul delegat e în registru), deci nu există tokenuri de verificat. Eticheta `src` din `DLV` o pune nodul delegat din identitatea sesiunii
  (nu din mesaj); datagrama rămâne protejată de sesiunea dintre cei doi membri, deci o etichetă falsă produce doar un pachet respins. Un singur salt, fără tranzit.
* **Alegere:** calea directă rămâne preferată. Pentru „relay” un nod alege, pentru fiecare destinație, nodul delegat cu care **amândoi** au sesiune (din `relays`) și
  cu cel mai mic RTT (probă la 10 s prin sesiune), altfel `oneqrelay` (WebSocket). Un nod delegat e folosit doar cât timp are cale directă proaspătă (< 40 s; keepalive 25 s).
  Un `NACK` (destinație neatașată) îl exclude 30 s pentru acea destinație. Handshake-ul și datele trec pe aceeași cale.
* **Limite:** găleată de jetoane pe total (cota din registru) și pe expeditor (jumătate), datagrame de cel mult 1600 B, `NACK` cel mult o dată pe secundă și pereche; un nod
  neîndreptățit (fără delegare în registru) ignoră `FWD`, iar `DLV`/`NACK` se acceptă doar de la nodurile pe care registrul le listează ca delegate.
* **Implementări:** `oneqnode.py` și clientul Rust (`engine.rs`: alegerea se calculează la fiecare tick în `Io.rly`, funcțiile de trimitere pun pachetul într-o coadă din care motorul îl
  trimite după eveniment). Teste: registru/API/admin, planul de date în memorie (Python), motorul Rust și laboratorul cu NAT-uri Linux (`test_nat_sim.py`: simetric + port-restricted prin
  nod delegat Python sau Rust, membri Python sau Rust).

## Al doilea factor al paginii de administrare (oneqtotp)

`oneqtotp.py` implementează TOTP (HMAC-SHA1, 6 cifre, 30 s, fereastră ±1) și `TotpStore`: fișier JSON mod 600 cu secretul (160 biți, base32), hash-urile a 10
coduri de recuperare și ultimul pas acceptat. `oneqadmin.AdminUI.h_login` verifică întâi parola și abia apoi consumă codul (într-un executor: scrierea fișierului
nu blochează bucla de evenimente); un singur mesaj de eroare pentru ambii factori; aceleași chei de blocare (`LoginGuard`) ca la parolă. Testat cu vectorii din
RFC 6238, cu reutilizarea codului, codurile de recuperare, blocarea și cazul în care starea nu se poate salva (cod refuzat).

## Dovada de posesie (oneqpop)

`oneqpop.py` (de sine stătător: doar `cryptography`) conține provocarea fără stare a serverului (`make_challenge`, `verify`), răspunsul nodului (`answer`, `Prover` cu cache) și
cheia serverului derivată din secretul federației. `oneqrelay.h_challenge` și `h_put_node` (câmpul `pop`; `meshdb.join_node(..., verified)` păstrează `pop: true` în înregistrarea nodului,
replicată; fără dovadă, un nod marcat nu se actualizează), `rendezvous_server` (aceeași schemă, plus `X-Oneq-Pop` la atașarea la relay), clientul Python (`oneqnode.Control._pop`,
`oneqtunel.Rendezvous.proof`) și cel Rust (`wire.rs::Identity::pop_answer`, `control.rs::pop_proof`). Descriere: README, „Dovada de posesie a cheii nodului”; engleză: POP.md.

## NAT (oneqnat)

*English version: [NAT.md](NAT.md).*

`oneqnat.py` conține codecul STUN (RFC 5389 + change-port), serverul (trei socket-uri UDP în `oneqrelay`), clasificarea, regula
`can_punch` și proba de accesibilitate; clientul Rust are aceeași logică în `client/core/src/nat.rs` (aceleași constante și același vector
de test RFC 5769). Registrul păstrează `nat` în înregistrarea de prezență (`{type, mapped, inbound}` plus, când există, `delta` (pas de alocare
al unui NAT simetric, ±1..64), `cgnat` (al doilea NAT) și `via` (`pcp|natpmp|upnp`); replicată, cu TTL; relay-ul nu lasă să treacă alte chei).
`can_punch` ia în calcul predicția și al doilea NAT (`oneqnat.py`, `nat.rs::can_punch_ex`); `oneqportmap.py` / `portmap.rs` vorbesc cu routerul;
`info.stun` conține și `change_port`. Testul de
filtrare vine dintr-un port pe care nodurile nu trimit niciodată: altfel NAT-ul ar lăsa răspunsul să treacă, iar un pachet nesolicitat
în plus ar muta maparea următoare (vezi README, „Sincronizarea hole punching-ului”). Rundele de punching sunt un tipar al ceasului relay-ului
(`PUNCH_PERIOD`, `PUNCH_CYCLE`, `PUNCH_ATTEMPTS`, `PUNCH_OFFSETS`), identic în Python și Rust; fără ceas măsurat nodul încearcă
continuu.

