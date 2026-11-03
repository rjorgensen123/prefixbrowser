# nbprefix – prefiks-utforsker for NetBox IPAM

`nbprefix` viser prefiksene i NetBox som et tre: hvilke prefikser som ligger under hvilke, hvor mye av
hver container som er brukt, og hvilke blokker som er ledige. Du kan se alle VRF-er samlet, gruppert per
VRF, bare globale prefikser, eller én VRF (eventuelt med de globale containerne som omslutter den), og
søke på tekst, IP-adresse eller prefiks. Hver rad har lenke rett inn i NetBox.

## To ting å vite

**Kjører lokalt på hver enkelt PC.** Scriptet starter en liten webserver på `127.0.0.1` og åpner
nettleseren din. Det er ingen sentral tjeneste og ingenting deles: hver bruker har sin egen kopi, sin egen
konfig og sitt eget API-token. Serveren svarer bare på localhost.

**Verktøyet er kun lesende.** Det gjør bare GET-kall mot NetBox-API-et (`/api/status/`, `/api/ipam/vrfs/`
og `/api/ipam/prefixes/`) og endrer aldri noe i NetBox. Bruk gjerne et token uten skrivetilgang.

## Krav

- Python 3.8 eller nyere. Kun standardbiblioteket, ingen `pip install`.
- Nettverkstilgang til NetBox-serveren og et API-token.

## Kom i gang

1. Legg `nbprefix.py`, `VERSION` og `start_nbprefix.bat` i en mappe på PC-en din.
2. Start med `start_nbprefix.bat` (Windows) eller `python nbprefix.py`.
3. Første gang åpnes en dialog for NetBox-URL og token. Trykk «Lagre og test». Innstillingene lagres i
   `nbprefix.json` ved siden av scriptet.

Flagg: `--port N` (standard 8765, neste ledige brukes automatisk), `--no-browser`, `--version`.

## API-token

NetBox 4.5 og nyere lager **v2-token**. Ved opprettelse viser NetBox nøkkel (Key) og token hver for seg.
Lim inn enten hele verdien `nbt_<nøkkel>.<token>` i token-feltet, eller token i token-feltet og nøkkelen i
feltet «Nøkkel (Key)». Eldre NetBox bruker **v1-token** (40 tegn), som limes inn som det er.
Verktøyet finner selv ut hvilken versjon det er og sender riktig `Authorization`-header.

Tokenet lagres i klartekst i `nbprefix.json` på din egen PC. Filen er i `.gitignore` og skal aldri
sjekkes inn.

## Konfigfil (`nbprefix.json`)

| Felt         | Beskrivelse                                              |
|--------------|----------------------------------------------------------|
| `netbox_url` | F.eks. `https://netbox.example.no`                       |
| `token`      | API-token, v1 eller v2 (se over)                         |
| `verify_tls` | `true` (standard) eller `false`                          |
| `ca_file`    | Valgfritt: sti til egen CA-fil (PEM)                     |
| `port`       | Valgfritt: port for den lokale webserveren               |

Se `nbprefix.example.json`.

## Bruk

- **Visning:** Alle VRF (samlet tre), Alle VRF (gruppert per VRF), Global, eller én VRF. For én VRF kan
  «globale containere» tas med.
- **IPv4 / IPv6:** filtrer på adressefamilie.
- **Vis ledig:** viser ledige blokker (grønt) mellom registrerte prefikser.
- **Søk:** fritekst (beskrivelse, tenant, VRF, scope, rolle, VLAN, status) eller en IP/prefiks. Et
  IP-søk finner det minste prefikset som inneholder adressen. Esc tømmer søket.
- **Lukk alle / Åpne +1 nivå:** styrer hvor dypt treet er utfoldet.
- **Oppdater fra NetBox:** henter alle prefikser på nytt. Data hentes ellers bare ved oppstart.
- **Dekning:** andel av et prefiks som er dekket av underprefikser. Oransje ved 90 % eller mer.

## Versjonering

Versjonsnummeret ligger i `VERSION` og endringene er beskrevet i `CHANGELOG.md`.
