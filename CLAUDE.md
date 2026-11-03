# Arbeidsregler for Claude Code i dette repoet

## Om prosjektet
- `nbprefix.py` er en lesende prefiks-utforsker for NetBox IPAM. Én fil, kun Python-standardbiblioteket,
  Python 3.8+. Ingen pip-avhengigheter skal innføres.
- Verktøyet er **kun lesende**: bare GET-kall mot NetBox. Aldri legg til kall som endrer noe i NetBox.
- Det kjører **lokalt på hver enkelt PC** (webserver på 127.0.0.1). Ikke gjør det til en delt tjeneste.
- Språk: norsk (bokmål) i svar, kodekommentarer, UI-tekster, changelog og commit-meldinger.

## Repo vs. kjørekopi
- Repoet er dette katalogen. Brukeren kjører verktøyet fra søstermappa `..\nbprefix`, som ikke er et git-repo
  og inneholder den ekte `nbprefix.json` (med API-token).
- Etter endringer i repoet: kopier `nbprefix.py` og `VERSION` til `..\nbprefix`. Rør aldri `nbprefix.json`
  eller `start_nbprefix.bat` der.

## Versjonering
- `VERSION` (x.y.z) skal alltid stemme med gjeldende versjon. Scriptet leser den ved oppstart.
- En versjon kan bestå av mange commits og endringer. **Ikke bump per commit.** Bump bare når brukeren sier at
  vi går til en ny versjon. Spør i én linje hvis det er uklart.
- `CHANGELOG.md`: før nye endringer inn under gjeldende versjon med overskriftene «Lagt til», «Endret»,
  «Rettet». Ny seksjon med dato (YYYY-MM-DD) når versjonen bumpes.

## Git
- Commit når brukeren ber om det, med norsk commit-melding. Brukeren pusher selv.
- Lag heller en ny commit enn å skrive om historikk, med mindre brukeren ber om det.
- `nbprefix.json` og `__pycache__/` er i `.gitignore` og skal aldri sjekkes inn. Token hører aldri hjemme i git.

## Testing
- Enhetstest token-normaliseringen (`normalize_token`, `token_hint`) ved endringer i autentisering.
- Lesende testkall mot brukerens NetBox er greit (det er det verktøyet gjør), men skriv aldri ut tokenet.
- Kjør aldri python fra kjøremappa med brukerens konfig for å teste `/api/config`; bruk en kladdekopi så
  `nbprefix.json` der ikke overskrives.
