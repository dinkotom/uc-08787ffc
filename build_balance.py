#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zůstatky rodinných účtů → šifrovaná statická stránka pro GitHub Pages.

Build: přečte notifikační e-maily České spořitelny z Gmailu (IMAP), vyparsuje
zůstatky, payload ZAŠIFRUJE (AES-GCM, klíč z hesla přes PBKDF2) a vygeneruje
stránku, kde se data dešifrují AŽ V PROHLÍŽEČI po zadání společného hesla.
Na Pages se nikdy nepublikují čisté hodnoty ani čísla účtů.

Prostředí / GitHub Secrets:
    BANK_EMAIL_USER       Gmail adresa
    BANK_EMAIL_PASSWORD   Gmail App Password
    BANK_ACCOUNTS         JSON mapa popisek->číslo účtu, např.
                          {"Rodina":"6086237013","Ota":"4886971073","Čeněk":"4886998073"}
    BALANCE_PASSWORD      heslo pro odemčení stránky (sdílené v rodině)
"""

import base64
import email
import hashlib
import imaplib
import json
import os
import re
import sys
from datetime import date, datetime, timedelta

IMAP_SERVER = "imap.gmail.com"
SENDER_EMAIL = "ceskasporitelna@csas.cz"
PBKDF2_ITERS = 200_000
OUT = "public"


# ---------------------------------------------------------------------------
# Zůstatky z e-mailů
# ---------------------------------------------------------------------------

def get_balances(accounts):
    """accounts: {popisek: cislo_uctu}. Vrátí ({popisek: int|None}, ts_str)."""
    results = {name: None for name in accounts}
    user = os.getenv("BANK_EMAIL_USER")
    pw = os.getenv("BANK_EMAIL_PASSWORD")
    ts = datetime.now().strftime("%-d.%-m.%Y %H:%M")
    if not user or not pw:
        print("VAROVÁNÍ: chybí BANK_EMAIL_*; zůstatky neznámé.", file=sys.stderr)
        return results, ts

    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, timeout=60)
        mail.login(user, pw)
        mail.select("inbox", readonly=True)
        since = (date.today() - timedelta(days=14)).strftime("%d-%b-%Y")
        status, messages = mail.search(None, f'(FROM "{SENDER_EMAIL}" SINCE "{since}")')
        if status == "OK" and messages[0]:
            for eid in reversed(messages[0].split()):
                if all(v is not None for v in results.values()):
                    break
                status, data = mail.fetch(eid, "(RFC822)")
                if status != "OK":
                    continue
                msg = email.message_from_bytes(data[0][1])
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() in ("text/html", "text/plain"):
                            p = part.get_payload(decode=True)
                            if p:
                                body += p.decode(errors="ignore")
                else:
                    p = msg.get_payload(decode=True)
                    if p:
                        body = p.decode(errors="ignore")

                for name, acc in accounts.items():
                    if results[name] is not None:
                        continue
                    padded = str(acc).zfill(16)
                    if padded in body:
                        idx = body.find(padded)
                        m = re.search(r"is\s*(?:<[^>]+>\s*)*([\d\s\xa0&nbsp;]+),(\d{2})\s*CZK",
                                      body[idx:idx + 500], re.IGNORECASE | re.DOTALL)
                        if m:
                            whole = re.sub(r"\D", "", m.group(1))
                            results[name] = int(round(float(f"{whole}.{m.group(2)}")))
        mail.close()
        mail.logout()
    except Exception as e:
        print(f"VAROVÁNÍ: čtení e-mailů selhalo: {e}", file=sys.stderr)
    return results, ts


# ---------------------------------------------------------------------------
# Šifrování (AES-GCM, klíč z hesla přes PBKDF2-SHA256)
# ---------------------------------------------------------------------------

def encrypt(payload: dict, password: str):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=32)
    ct = AESGCM(key).encrypt(iv, json.dumps(payload, ensure_ascii=False).encode("utf-8"), None)
    b = lambda x: base64.b64encode(x).decode()
    return b(salt), b(iv), b(ct)


# ---------------------------------------------------------------------------
# Stránka
# ---------------------------------------------------------------------------

PAGE = """<!DOCTYPE html>
<html lang="cs">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta http-equiv="refresh" content="900">
<meta name="theme-color" content="#0c0f14">
<title>Účty</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500..700&family=IBM+Plex+Mono:wght@500;600;700&display=swap" rel="stylesheet">
<style>
  :root{--bg:#0c0f14; --panel:#141923; --ink:#eef1f6; --muted:#7e8aa0;
    --line:rgba(255,255,255,.09); --gold:#d8b66b; --green:#4cc99a;}
  *{box-sizing:border-box;}
  body{margin:0; min-height:100vh; color:var(--ink); background:var(--bg);
    font-family:"IBM Plex Mono",ui-monospace,monospace; padding:0 16px 50px;
    background-image:radial-gradient(120% 55% at 50% -10%, rgba(216,182,107,.10), transparent 60%);
    background-attachment:fixed; display:flex; flex-direction:column; align-items:center;}
  .wrap{width:100%; max-width:460px;}
  header{padding:46px 2px 8px;}
  .kicker{font-size:.7rem; letter-spacing:.3em; text-transform:uppercase; color:var(--muted);}
  h1{font-family:"Fraunces",Georgia,serif; font-weight:600; font-size:clamp(2.2rem,9vw,3rem);
    margin:.12em 0 .1em; letter-spacing:-.02em;}
  h1 .d{color:var(--gold);}
  .sub{font-size:.74rem; color:var(--muted);}

  .lock{margin-top:30px; background:var(--panel); border:1px solid var(--line);
    border-radius:18px; padding:26px 22px; text-align:center;}
  .lock .ico{font-size:1.6rem;}
  .lock p{color:var(--muted); font-size:.82rem; margin:10px 0 16px;}
  .lock form{display:flex; gap:8px;}
  .lock input{flex:1; background:#0c0f14; border:1px solid var(--line); border-radius:11px;
    color:var(--ink); font-family:inherit; font-size:1rem; padding:12px 14px;}
  .lock input:focus{outline:none; border-color:var(--gold);}
  .lock button{background:var(--gold); color:#1a1404; border:0; border-radius:11px;
    font-family:inherit; font-weight:700; font-size:.95rem; padding:12px 18px; cursor:pointer;}
  .err{color:#ff7a6b; font-size:.78rem; margin-top:10px; min-height:1em;}

  #data{margin-top:24px; display:none;}
  #data.on{display:block;}
  .row{background:var(--panel); border:1px solid var(--line); border-radius:16px;
    padding:16px 18px; margin:10px 0; display:flex; align-items:baseline; justify-content:space-between;
    animation:rise .5s cubic-bezier(.2,.7,.2,1) both; animation-delay:calc(var(--i)*60ms);}
  @keyframes rise{from{opacity:0; transform:translateY(10px);} to{opacity:1; transform:none;}}
  .row .lbl{font-family:"Fraunces",serif; font-size:1.15rem; font-weight:600;}
  .row .amt{font-size:1.45rem; font-weight:700; letter-spacing:-.01em; font-variant-numeric:tabular-nums;}
  .row .amt .cur{font-size:.8rem; color:var(--muted); font-weight:600; margin-left:4px;}
  .row .amt.unk{color:var(--muted); font-size:1.1rem;}
  .when{text-align:center; color:var(--muted); font-size:.72rem; margin-top:14px;}
  .lockbtn{display:block; margin:18px auto 0; background:none; border:1px solid var(--line);
    color:var(--muted); border-radius:999px; padding:7px 16px; font-family:inherit;
    font-size:.74rem; cursor:pointer;}

  footer{margin-top:26px; text-align:center; font-size:.68rem; color:var(--muted);}
  footer a{color:var(--gold);}
  @media (prefers-reduced-motion:reduce){*{animation:none!important;}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="kicker">Rodinné finance</div>
    <h1>Účty<span class="d">.</span></h1>
    <div class="sub">Soukromé · chráněno heslem</div>
  </header>

  <div id="lock" class="lock">
    <div class="ico">🔒</div>
    <p>__LOCKMSG__</p>
    <form id="f" __FORMDISABLED__>
      <input id="pw" type="password" inputmode="text" autocomplete="current-password" placeholder="Heslo" autofocus>
      <button type="submit">Odemknout</button>
    </form>
    <div class="err" id="err"></div>
  </div>

  <div id="data"></div>

  <footer><a href="https://dinkotom.github.io/domov-60de93c6/">← Doma</a> · zdroj: e-maily ČS · obnova á 15 min</footer>
</div>

<script>
  var ENC = __ENC__;          // {salt, iv, ct, iter} nebo null
  var lock=document.getElementById('lock'), dataEl=document.getElementById('data'),
      err=document.getElementById('err'), form=document.getElementById('f'), pwEl=document.getElementById('pw');

  function b64(s){ return Uint8Array.from(atob(s), function(c){return c.charCodeAt(0);}); }
  function fmt(n){ return (typeof n==='number') ? n.toLocaleString('cs-CZ') : null; }

  async function decrypt(pw){
    var salt=b64(ENC.salt), iv=b64(ENC.iv), ct=b64(ENC.ct);
    var km=await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
    var key=await crypto.subtle.deriveKey({name:'PBKDF2', salt:salt, iterations:ENC.iter, hash:'SHA-256'},
              km, {name:'AES-GCM', length:256}, false, ['decrypt']);
    var pt=await crypto.subtle.decrypt({name:'AES-GCM', iv:iv}, key, ct);
    return JSON.parse(new TextDecoder().decode(pt));
  }

  function render(payload){
    var rows = payload.rows.map(function(r, i){
      var v = fmt(r.balance);
      var amt = (v===null)
        ? '<span class="amt unk">—</span>'
        : '<span class="amt">'+v+'<span class="cur">Kč</span></span>';
      return '<div class="row" style="--i:'+i+'"><span class="lbl">'+
             r.label.replace(/[<>&]/g,'')+'</span>'+amt+'</div>';
    }).join('');
    dataEl.innerHTML = rows +
      '<div class="when">aktualizováno '+ (payload.ts||'') +'</div>'+
      '<button class="lockbtn" onclick="lockNow()">Zamknout</button>';
    dataEl.classList.add('on'); lock.style.display='none';
  }
  function lockNow(){ try{sessionStorage.removeItem('bpw');}catch(e){}; location.reload(); }

  async function unlock(pw, silent){
    try{
      var payload=await decrypt(pw);
      try{ sessionStorage.setItem('bpw', pw); }catch(e){}
      render(payload);
    }catch(e){
      if(!silent){ err.textContent='Špatné heslo.'; pwEl.value=''; pwEl.focus(); }
    }
  }

  if(ENC && form){
    form.addEventListener('submit', function(e){ e.preventDefault(); err.textContent=''; unlock(pwEl.value, false); });
    var saved=null; try{ saved=sessionStorage.getItem('bpw'); }catch(e){}
    if(saved) unlock(saved, true);
  }
</script>
</body>
</html>
"""


def build_page(enc, configured):
    if configured and enc:
        salt, iv, ct = enc
        enc_js = json.dumps({"salt": salt, "iv": iv, "ct": ct, "iter": PBKDF2_ITERS})
        lockmsg = "Zadej rodinné heslo pro zobrazení zůstatků."
        formdis = ""
    else:
        enc_js = "null"
        lockmsg = "Stránka zatím není nakonfigurovaná (chybí secrets)."
        formdis = "style=\"display:none\""
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "index.html"), "w", encoding="utf-8") as f:
        f.write(PAGE.replace("__ENC__", enc_js)
                    .replace("__LOCKMSG__", lockmsg)
                    .replace("__FORMDISABLED__", formdis))


def main():
    password = os.getenv("BALANCE_PASSWORD")
    if not password:
        print("VAROVÁNÍ: chybí BALANCE_PASSWORD – stavím nenakonfigurovanou stránku.", file=sys.stderr)
        build_page(None, configured=False)
        return

    try:
        accounts = json.loads(os.getenv("BANK_ACCOUNTS", "{}"))
    except json.JSONDecodeError:
        sys.exit("BANK_ACCOUNTS není platný JSON.")
    if not accounts:
        print("VAROVÁNÍ: prázdné BANK_ACCOUNTS.", file=sys.stderr)

    balances, ts = get_balances(accounts)
    payload = {"ts": ts, "rows": [{"label": name, "balance": balances[name]} for name in accounts]}
    enc = encrypt(payload, password)
    build_page(enc, configured=True)
    znamych = sum(1 for v in balances.values() if v is not None)
    print(f"Hotovo: {znamych}/{len(accounts)} zůstatků, zašifrováno.", file=sys.stderr)


if __name__ == "__main__":
    main()
