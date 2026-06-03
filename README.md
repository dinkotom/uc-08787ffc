# Účty – zůstatky rodinných účtů (šifrované)

Statická stránka s **šifrovanými** zůstatky tří rodinných účtů ČS. Build (GitHub
Actions) přečte notifikační e-maily ČS z Gmailu (IMAP), zůstatky **zašifruje**
(AES-GCM, klíč z hesla přes PBKDF2) a publikuje na Pages **jen šifrovaný text**.
Dešifrování probíhá **až v prohlížeči** po zadání společného hesla (WebCrypto).
Čisté hodnoty ani čísla účtů se na Pages nikdy nedostanou. `noindex`.

## Potřebné GitHub Secrets
| Secret | Obsah |
|---|---|
| `BALANCE_PASSWORD` | heslo pro odemčení stránky (sdílené v rodině) |
| `BANK_EMAIL_USER` | Gmail adresa |
| `BANK_EMAIL_PASSWORD` | Gmail App Password |
| `BANK_ACCOUNTS` | JSON popisek→účet, např. `{"Rodina":"6086237013","Ota":"...","Čeněk":"..."}` |

Bez `BALANCE_PASSWORD` se nasadí „nenakonfigurovaná" stránka.

## Build
GitHub Actions ~každých 30 min. Lokální náhled (s vymyšlenými daty):
```python
import build_balance as B
B.build_page(B.encrypt({"ts":"…","rows":[{"label":"Rodina","balance":1000}]}, "heslo"), True)
```
