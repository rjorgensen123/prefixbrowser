# Changelog

Alle vesentlige endringer i nbprefix dokumenteres her. Versjonsnummeret ligger i `VERSION`
(x.y.z, der z økes for hver endring) og leses av scriptet ved oppstart.

## [0.1.0] - 2026-11-03

### Lagt til
- README.md som beskriver verktøyet, at det kjører lokalt på hver enkelt PC, og at det kun leser fra NetBox.
- Støtte for NetBox v2-token (NetBox 4.5+): `nbt_<nøkkel>.<token>` sendes som `Authorization: Bearer`.
  v1-token (40 tegn) sendes fortsatt som `Authorization: Token`.
- Tokenet kan oppgis som komplett `nbt_<nøkkel>.<token>`, som `<nøkkel>.<token>` uten prefiks,
  eller som nøkkel og token hver for seg (nytt felt "Nøkkel (Key)" i innstillingsdialogen).
- Forklarende hjelpetekst når NetBox avviser tokenet (f.eks. bare token-delen av et v2-token limt inn).
- Statuslinjen viser hvilken token-versjon som er i bruk.
- `VERSION`-fil og denne changeloggen. Versjonen vises ved oppstart, i User-Agent og med `--version`.
- `.gitignore` som holder `nbprefix.json` (lokal konfig med token) og `__pycache__` utenfor git.

### Endret
- Eksempelkonfig og docstring dokumenterer begge tokenformatene.

## [0.0.1] - 2026-11-03

### Lagt til
- Første utgave: lesende prefiks-utforsker for NetBox IPAM med lokal webserver, tre-visning per VRF,
  ledige blokker, dekningsgrad og søk på tekst/IP/prefiks. Kun standardbiblioteket.
