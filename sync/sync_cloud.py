# -*- coding: utf-8 -*-
# nolio_sync.py - Synchro Nolio -> data.json -> GitHub Pages
#
# Version "compte coach" : un seul token (celui de Noah), qui donne acces a
# tous les coureurs geres via /get/athletes/ et le parametre athlete_id.
# Les coureurs n'ont plus besoin de s'autoriser un par un.
#
# Le token coach est lu dans tokens.json sur GitHub (la ou le Worker
# Cloudflare l'enregistre quand on passe par autoriser.html).

import json
import os
import sys
import time
import base64
from datetime import datetime, timedelta, timezone
from urllib.request import urlopen, Request
from urllib.parse import urlencode
from urllib.error import HTTPError

# -- CONFIGURATION ------------------------------------------------------------
# Version cloud (GitHub Actions) : les secrets viennent des variables d'environnement
OUTPUT_FILE = "data.json"
TOKENS_BACKUP = None

GITHUB_TOKEN  = os.environ["GH_PAT"]
GITHUB_REPO   = "knechtnoah-afk/nolio-coach"   # depot public (appli + data.enc.json chiffre)
PRIVATE_REPO  = "knechtnoah-afk/nolio-private" # depot prive (tokens.json + config.json)
ENC_FILE      = "data.enc.json"
GITHUB_BRANCH = "main"

# App Nolio "Multi-user" (meme app que autoriser.html / le Worker)
NOLIO_CLIENT_ID     = "LDiR5WZ4opOj8mURtmByci5MppyfqdvQEzp7Aye8"
NOLIO_CLIENT_SECRET = os.environ["NOLIO_CLIENT_SECRET"]
NOLIO_BASE          = "https://www.nolio.io/api"

COACH_ID = "8254"  # Noah Knecht

DAYS_HISTORY = 95
DAYS_PREV_30 = 30


# -- HTTP NOLIO ---------------------------------------------------------------
def nolio_get(path, token, params=None):
    url = NOLIO_BASE + "/" + path
    if params:
        url += "?" + urlencode(params)
    req = Request(url, headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    for attempt in range(3):
        try:
            with urlopen(req, timeout=60) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            print("    WARN GET " + path + " -> HTTP " + str(e.code) + ": " + body[:150])
            return None
        except Exception as e:
            # coupure reseau / telechargement incomplet -> on reessaie
            print("    WARN GET " + path + " -> " + str(e)[:80] + " (essai " + str(attempt + 1) + "/3)")
            time.sleep(3)
    return None


def nolio_refresh(refresh_token):
    creds = base64.b64encode((NOLIO_CLIENT_ID + ":" + NOLIO_CLIENT_SECRET).encode()).decode()
    body = urlencode({"grant_type": "refresh_token", "refresh_token": refresh_token}).encode()
    req = Request(NOLIO_BASE + "/token/", data=body, method="POST", headers={
        "Authorization": "Basic " + creds,
        "Content-Type": "application/x-www-form-urlencoded"
    })
    try:
        with urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except HTTPError as e:
        print("  ERREUR refresh HTTP " + str(e.code) + ": " + e.read().decode("utf-8", errors="ignore")[:200])
        return None
    except Exception as e:
        print("  ERREUR refresh: " + str(e))
        return None


# -- HTTP GITHUB --------------------------------------------------------------
GH_HEADERS = {
    "Authorization": "token " + GITHUB_TOKEN,
    "Accept": "application/vnd.github.v3+json",
    "Content-Type": "application/json",
    "User-Agent": "nolio-sync"
}

def gh_read(path, repo=None):
    """Retourne (contenu_str, sha) ou (None, None)."""
    url = "https://api.github.com/repos/" + (repo or GITHUB_REPO) + "/contents/" + path + "?ref=" + GITHUB_BRANCH
    try:
        with urlopen(Request(url, headers=GH_HEADERS), timeout=20) as r:
            j = json.loads(r.read())
            return (base64.b64decode(j["content"]).decode("utf-8") if j.get("content") else ""), j["sha"]
    except HTTPError as e:
        print("  ERREUR GitHub lecture " + path + " -> HTTP " + str(e.code))
        return None, None


def gh_write(path, content_str, message, repo=None):
    _, sha = gh_read(path, repo)
    payload = {
        "message": message,
        "content": base64.b64encode(content_str.encode("utf-8")).decode("ascii"),
        "branch": GITHUB_BRANCH
    }
    if sha:
        payload["sha"] = sha
    url = "https://api.github.com/repos/" + (repo or GITHUB_REPO) + "/contents/" + path
    try:
        req = Request(url, data=json.dumps(payload).encode("utf-8"), headers=GH_HEADERS, method="PUT")
        with urlopen(req, timeout=60) as r:
            r.read()
        print("  OK " + path + " pousse sur GitHub")
        return True
    except HTTPError as e:
        print("  ERREUR GitHub ecriture " + path + " -> HTTP " + str(e.code) + ": " + e.read().decode("utf-8", errors="ignore")[:200])
        return False



# -- CHIFFREMENT DE data.json (AES-256-GCM, cle derivee du mot de passe) -----
PBKDF2_ITER = 250000
_PW = {}

def data_password():
    if "pw" not in _PW:
        txt, _ = gh_read("config.json", PRIVATE_REPO)
        pw = (json.loads(txt).get("data_password") if txt else None) or os.environ.get("DATA_PASSWORD")
        if not pw:
            sys.exit("Mot de passe des donnees introuvable (config.json du depot prive).")
        _PW["pw"] = pw
    return _PW["pw"]


def _aes():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        import subprocess
        subprocess.call([sys.executable, "-m", "pip", "install", "--quiet", "cryptography"])
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM


def encrypt_json(text):
    import gzip, hashlib
    AESGCM = _aes()
    salt, iv = os.urandom(16), os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", data_password().encode("utf-8"), salt, PBKDF2_ITER, 32)
    ct = AESGCM(key).encrypt(iv, gzip.compress(text.encode("utf-8")), None)
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return json.dumps({"v": 1, "kdf": "pbkdf2-sha256", "iter": PBKDF2_ITER, "z": "gzip",
                       "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)})


def decrypt_json(enc_text):
    import gzip, hashlib
    AESGCM = _aes()
    e = json.loads(enc_text)
    key = hashlib.pbkdf2_hmac("sha256", data_password().encode("utf-8"), base64.b64decode(e["salt"]), int(e["iter"]), 32)
    raw = AESGCM(key).decrypt(base64.b64decode(e["iv"]), base64.b64decode(e["ct"]), None)
    return (gzip.decompress(raw) if e.get("z") == "gzip" else raw).decode("utf-8")

# -- TOKEN COACH --------------------------------------------------------------
def get_coach_token():
    content, _ = gh_read("tokens.json", PRIVATE_REPO)
    if not content:
        sys.exit("Impossible de lire tokens.json dans le depot prive.")
    tokens_data = json.loads(content)
    coach = next((a for a in tokens_data.get("athletes", []) if str(a.get("athlete_id")) == COACH_ID), None)
    if not coach:
        sys.exit("Token coach introuvable dans tokens.json -> repasse par autoriser.html.")

    exp = None
    try:
        exp = datetime.fromisoformat(coach.get("expires_at", "").replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
    except Exception:
        pass

    now = datetime.now(timezone.utc)
    if exp and exp > now + timedelta(minutes=60):
        print("Token coach valide encore " + str(int((exp - now).total_seconds() // 3600)) + "h")
        return coach["access_token"]

    print("Token coach expire -> renouvellement...")
    new = nolio_refresh(coach.get("refresh_token", ""))
    if not new or not new.get("access_token"):
        sys.exit("Renouvellement impossible -> ouvre autoriser.html et reconnecte-toi (30 secondes).")

    coach["access_token"] = new["access_token"]
    coach["refresh_token"] = new.get("refresh_token", coach.get("refresh_token"))
    coach["expires_at"] = (now + timedelta(seconds=new.get("expires_in", 86400))).isoformat()
    tokens_data["updated_at"] = now.isoformat()
    out = json.dumps(tokens_data, ensure_ascii=False, indent=2)
    gh_write("tokens.json", out, "token coach renouvele", PRIVATE_REPO)
    print("Token coach renouvele.")
    return coach["access_token"]


# -- EQUIPES ------------------------------------------------------------------
def team_code(team_name):
    n = (team_name or "").lower()
    if "nice" in n or "metropole" in n or "azur" in n:
        return "NMCA"
    if "noah" in n or "knecht" in n:
        return "NK"
    return None



# -- RESUME DES SORTIES REALISEES (lecture du fichier .fit) --------------------
# Ecrit pour chaque sortie velo ce qui a ete fait, ex :
# "30min Z2 (212W) - 6x 14min a 272W (Z3) avec 6min30 recup - 30min Z2 (221W)"
RESUME_VERSION = 1
MAX_NEW_RESUMES = 150   # analyses nouvelles max par synchro (le reste a la suivante)
VELO_WORDS = ("velo", "v\u00e9lo", "home trainer", "vtt", "gravel", "cycl", "bike", "route", "piste", "zwift")

BLOCK = 5  # secondes par bloc
PENK = 6

def zone(p, ftp):
    r = p / float(ftp)
    if r < 0.55: return 1
    if r < 0.76: return 2
    if r < 0.91: return 3
    if r < 1.06: return 4
    if r < 1.21: return 5
    return 6

def fmt_dur(sec):
    sec = int(round(sec))
    if sec < 90: return "%ds" % sec
    m = int(round(sec / 60.0))
    if m < 60: return "%dmin" % m
    h, m = divmod(m, 60)
    return "%dh%02d" % (h, m) if m else "%dh" % h

def fmt_rep(sec):
    # durees de repetitions : arrondi propre (30s, 1min, 1min30, 12min...)
    sec = int(round(sec))
    if sec < 52: return "%ds" % int(round(sec / 5.0) * 5)
    if sec < 75: return "1min"
    if sec < 600:
        half = int(round(sec / 30.0))
        m, s = divmod(half * 30, 60)
        return "%dmin%s" % (m, "30" if s else "")
    return fmt_dur(sec)

def _segment(x, minlen, pen):
    # segmentation optimale (moyennes constantes par morceaux), cout = SSE + pen par segment
    n = len(x)
    S = [0.0] * (n + 1); Q = [0.0] * (n + 1)
    for i, v in enumerate(x):
        S[i + 1] = S[i] + v; Q[i + 1] = Q[i] + v * v
    def cost(a, b):
        s = S[b] - S[a]; return (Q[b] - Q[a]) - s * s / (b - a)
    INF = float("inf")
    F = [INF] * (n + 1); F[0] = -pen; last = [0] * (n + 1)
    cands = [0]
    for t in range(minlen, n + 1):
        best, arg = INF, 0
        for s in cands:
            if t - s < minlen: continue
            c = F[s] + cost(s, t) + pen
            if c < best: best, arg = c, s
        F[t], last[t] = best, arg
        # elagage PELT
        cands = [s for s in cands if t - s < minlen or F[s] + cost(s, t) <= F[t]]
        if t - minlen + 1 >= 0: cands.append(t - minlen + 1)
    if F[n] == INF:
        return [(0, n)]
    cuts, t = [], n
    while t > 0:
        s = last[t]; cuts.append((s, t)); t = s
    return cuts[::-1]

def analyse(watts, ftp):
    """watts: 1 valeur/seconde (0/None = roue libre ou arret). Renvoie (texte, detail_reps)."""
    import math
    if not watts or not ftp or len(watts) < 600:
        return "", "", []
    # 1) retirer les arrets (>= 60 s a 0 W)
    w, run = [], []
    for v in watts:
        v = float(v or 0)
        if v <= 0:
            run.append(0.0); continue
        if len(run) < 60: w.extend(run)
        run = []; w.append(v)
    if len(run) < 60: w.extend(run)
    if len(w) < 600:
        return "", "", []
    N = len(w)
    # sommes cumulees des valeurs non nulles (moyenne "hors roue libre", comme Nolio)
    cs = [0.0] * (N + 1); cn = [0] * (N + 1)
    for i, v in enumerate(w):
        cs[i + 1] = cs[i] + v; cn[i + 1] = cn[i] + (1 if v > 0 else 0)
    def pw(a, b):  # a, b en blocs
        a, b = a * BLOCK, min(b * BLOCK, N)
        k = cn[b] - cn[a]
        return (cs[b] - cs[a]) / k if k else 0.0
    nb = (N + BLOCK - 1) // BLOCK
    blocks = [pw(i, i + 1) for i in range(nb)]
    d = sorted(abs(blocks[i + 1] - blocks[i]) for i in range(nb - 1))
    sig = max(d[len(d) // 2] / 0.954, 0.04 * ftp) if d else 0.1 * ftp
    pen = 2.0 * sig * sig * math.log(nb) * PENK
    hard_thr = 0.76 * ftp
    segs = [{"a": a, "b": b} for a, b in _segment(blocks, 4, pen)]

    def finish(lst):
        for s in lst:
            s["p"] = pw(s["a"], s["b"]); s["dur"] = (s["b"] - s["a"]) * BLOCK; s["z"] = zone(s["p"], ftp)
        return lst
    def fuse(lst):  # fusion des voisins de meme nature
        out = []
        for s in lst:
            if out and out[-1]["hard"] == s["hard"]:
                out[-1]["b"] = s["b"]
            else:
                out.append(dict(s))
        return finish(out)
    for s in finish(segs):
        s["hard"] = s["p"] >= hard_thr
    m = fuse(segs)
    # 2) combler les petits trous dans un effort (descente, carrefour) - en une passe, sans effet boule de neige
    # a) roue libre courte (< 45 s, quasi 0 W) entre deux efforts = meme effort
    for k in range(1, len(m) - 1):
        g, L, R = m[k], m[k - 1], m[k + 1]
        if (not g["hard"]) and L["hard"] and R["hard"] and g["dur"] <= 45 and g["p"] < 0.3 * ftp:
            g["hard"] = True
    m = fuse(m)
    # b) petit trou (< 2 min et < 1/4 de l'effort voisin)
    fill = set()
    for k in range(1, len(m) - 1):
        g, L, R = m[k], m[k - 1], m[k + 1]
        if (not g["hard"]) and L["hard"] and R["hard"] and g["dur"] <= 120 and g["dur"] <= 0.25 * max(L["dur"], R["dur"]):
            fill.add(k)
    for k in fill:
        m[k]["hard"] = True
    m = fuse(m)
    for s in m:  # un "effort" retombe sous le seuil apres fusion -> endurance
        if s["hard"] and s["p"] < hard_thr: s["hard"] = False
    m = fuse(m)
    # relance courte au milieu d'une longue partie facile (pas une repetition courte) -> facile
    changed = True
    while changed:
        changed = False
        for k in range(len(m)):
            s = m[k]
            if not s["hard"] or s["dur"] >= 120: continue
            nb_ = [m[x]["dur"] for x in (k - 1, k + 1) if 0 <= x < len(m)]
            if nb_ and min(nb_) >= 2 * s["dur"] and sum(nb_) >= 240:
                s["hard"] = False; m = fuse(m); changed = True; break
    # 3) repetitions : efforts consecutifs de duree et de puissance proches
    items, i = [], 0
    while i < len(m):
        s = m[i]
        if not s["hard"]:
            items.append(["easy", s]); i += 1; continue
        grp, rec, j = [s], [], i
        while j + 2 < len(m):
            r, nx = m[j + 1], m[j + 2]
            md = sum(g["dur"] for g in grp) / len(grp); mp = sum(g["p"] for g in grp) / len(grp)
            if (nx["hard"] and abs(nx["dur"] - md) <= 0.35 * max(nx["dur"], md) + 30
                    and r["dur"] <= max(1.5 * md, 360) and abs(nx["p"] - mp) <= 0.15 * mp
                    and (md >= 120 or zone(mp, ftp) >= 5)):
                grp.append(nx); rec.append(r); j += 2
            else:
                break
        if len(grp) >= 2:
            items.append(["reps", grp, rec]); i = j + 1
        else:
            items.append(["hard", s]); i += 1
    # 4) efforts isoles : < 2 min = relance (sprint si Z6) ; Z3 < 10 min = bosse -> fondus dans l'endurance
    sprints, bosses = 0, []
    out = []
    for it in items:
        if it[0] == "hard":
            s = it[1]
            if s["dur"] < 120:
                if s["p"] >= 1.21 * ftp: sprints += 1
                it = ["easy", s]
            elif s["z"] <= 3 and s["dur"] < 600:
                bosses.append(s); it = ["easy", s]
        if it[0] == "easy" and out and out[-1][0] == "easy":
            out[-1][1] = finish([{"a": out[-1][1]["a"], "b": it[1]["b"]}])[0]
        else:
            if it[0] == "easy": it = ["easy", finish([{"a": it[1]["a"], "b": it[1]["b"]}])[0]]
            out.append(it)
    items = out
    A = u"\u00e0"; REC = u"r\u00e9cup"; X = u"\u00d7"; DOT = u" \u00b7 "
    parts, details, blk = [], [], []
    for it in items:
        if it[0] == "easy":
            s = it[1]
            if s["dur"] < 120: continue
            parts.append(u"%s Z%d (%dW)" % (fmt_dur(s["dur"]), s["z"], round(s["p"])))
            blk.append({"t": "easy", "d": int(s["dur"]), "p": int(round(s["p"])), "z": s["z"]})
        elif it[0] == "hard":
            s = it[1]
            parts.append(u"%s %s %dW (Z%d)" % (fmt_rep(s["dur"]), A, round(s["p"]), s["z"]))
            blk.append({"t": "hard", "d": int(s["dur"]), "p": int(round(s["p"])), "z": s["z"]})
        else:
            grp, rec = it[1], it[2]
            tot = sum(g["dur"] for g in grp)
            p = sum(g["p"] * g["dur"] for g in grp) / tot
            r = sum(x["dur"] for x in rec) / len(rec)
            parts.append(u"%d%s %s %s %dW (Z%d) avec %s %s" % (
                len(grp), X, fmt_rep(tot / len(grp)), A, round(p), zone(p, ftp), fmt_rep(r), REC))
            blk.append({"t": "reps", "n": len(grp), "d": int(round(tot / len(grp))), "p": int(round(p)), "z": zone(p, ftp),
                        "r": int(round(r)), "ps": [int(round(g["p"])) for g in grp], "ds": [int(g["dur"]) for g in grp]})
            details.append(u"%d%s %s : %s W" % (len(grp), X, fmt_rep(tot / len(grp)), DOT.join(str(int(round(g["p"]))) for g in grp)))
    extra = []
    if bosses:
        bd = sum(b["dur"] for b in bosses); bp = sum(b["p"] * b["dur"] for b in bosses) / bd
        extra.append(u"dont %d mont\u00e9e%s en Z3 (%s au total, %dW)" % (len(bosses), "s" if len(bosses) > 1 else "", fmt_dur(bd), round(bp)))
    if sprints:
        extra.append(u"%d sprint%s" % (sprints, "s" if sprints > 1 else ""))
    txt = DOT.join(parts)
    if extra: txt += u" \u2014 " + ", ".join(extra)
    if sprints: blk.append({"t": "sprints", "n": sprints})
    return txt, u" | ".join(details), blk


def _fitdecode():
    try:
        import fitdecode
    except ImportError:
        import subprocess
        subprocess.call([sys.executable, "-m", "pip", "install", "--quiet", "fitdecode"])
        import fitdecode
    return fitdecode


def fit_power_1hz(raw):
    """Courbe de puissance 1 point/seconde depuis un fichier .fit (pauses retirees)."""
    import io
    fitdecode = _fitdecode()
    pts = []
    with fitdecode.FitReader(io.BytesIO(raw), check_crc=fitdecode.CrcCheck.DISABLED,
                             error_handling=fitdecode.ErrorHandling.IGNORE) as fr:
        for fr_ in fr:
            if fr_.frame_type != fitdecode.FIT_FRAME_DATA or fr_.name != "record":
                continue
            ts = fr_.get_value("timestamp", fallback=None)
            if ts is None:
                continue
            pw = fr_.get_value("power", fallback=None)
            pts.append((ts, pw))
    if not pts:
        return []
    with_pw = sum(1 for _, v in pts if v is not None)
    if with_pw < 0.5 * len(pts):
        return []  # pas de capteur de puissance
    pts.sort(key=lambda x: x[0])
    out, prev = [], None
    for ts, pw in pts:
        v = float(pw or 0)
        if prev is not None:
            dt = int(round((ts - prev).total_seconds()))
            if dt <= 0:
                continue
            if 1 < dt <= 5:
                out.extend([v] * (dt - 1))
        out.append(v)
        prev = ts
    return out


def is_velo(t):
    n = ((t.get("sport") or "") + " " + (t.get("name") or "")).lower()
    return any(wd in n for wd in VELO_WORDS) and "course" not in (t.get("sport") or "").lower()


def load_previous_resumes():
    """Resumes deja calcules (data.json precedent) -> on ne refait pas le travail."""
    prev = {}
    txt = None
    try:
        with open(ENC_FILE, encoding="utf-8") as f:
            txt = decrypt_json(f.read())
    except Exception as e1:
        try:
            with urlopen("https://raw.githubusercontent.com/" + GITHUB_REPO + "/" + GITHUB_BRANCH + "/" + ENC_FILE, timeout=60) as r:
                txt = decrypt_json(r.read().decode("utf-8"))
        except Exception as e:
            print("  (pas de donnees precedentes: " + str(e)[:60] + ")")
    if not txt:
        return prev
    try:
        for a in json.loads(txt).get("athletes", []):
            for t in (a.get("trainings_90d") or []) + (a.get("trainings_prev_30d") or []):
                if t.get("resume_v") == RESUME_VERSION and t.get("nolio_id"):
                    prev[t["nolio_id"]] = (t.get("resume") or "", t.get("resume_detail") or "", t.get("resume_blocks") or [])
    except Exception as e:
        print("  WARN lecture data.json precedent: " + str(e)[:80])
    return prev


_budget = {"left": MAX_NEW_RESUMES}

def add_resumes(trainings, prev):
    ftp_fallback = next((t.get("ftp") for t in trainings if t.get("ftp")), None)
    done = new = 0
    for t in sorted(trainings, key=lambda x: x.get("date_start") or "", reverse=True):
        tid = t.get("nolio_id")
        if tid in prev:
            t["resume"], t["resume_detail"], t["resume_blocks"] = prev[tid]; t["resume_v"] = RESUME_VERSION; done += 1
            continue
        if not is_velo(t) or (t.get("duration") or 0) < 1200 or not t.get("file_url") or not t.get("avg_watt"):
            continue
        ftp = t.get("ftp") or ftp_fallback
        if not ftp or _budget["left"] <= 0:
            continue
        _budget["left"] -= 1
        try:
            with urlopen(Request(t["file_url"], headers={"User-Agent": "nolio-sync"}), timeout=60) as r:
                raw = r.read()
            txt, det, blk = analyse(fit_power_1hz(raw), float(ftp))
        except Exception as e:
            print("    WARN resume " + str(tid) + ": " + str(e)[:80])
            continue
        t["resume"], t["resume_detail"], t["resume_blocks"], t["resume_v"] = txt, det, blk, RESUME_VERSION
        new += 1
    return done, new


# -- SEANCES PREVUES (pour la mini IA : comparer prevu / realise) -------------
DEBUG_PLANNED = {}

def _num(v):
    try:
        return float(v)
    except Exception:
        return None


def norm_plan_step(st):
    """Normalise une etape du structured_workout Nolio (format v1 non documente -> lecture prudente)."""
    if not isinstance(st, dict):
        return None
    typ = str(st.get("type") or st.get("kind") or "").lower()
    sub = st.get("steps")
    if isinstance(sub, list) and (typ in ("repetition", "repeat", "repetitions", "loop") or st.get("times") or st.get("value")):
        n = int(_num(st.get("value") or st.get("times") or st.get("repetitions") or 1) or 1)
        return {"t": "reps", "n": n, "steps": [x for x in (norm_plan_step(y) for y in sub) if x]}
    dtype = str(st.get("step_duration_type") or "").lower()
    dval = st.get("step_duration_value")
    if dval is None:
        dv = st.get("duration")
        dval = dv.get("value") if isinstance(dv, dict) else dv
    out = {"t": "step", "it": str(st.get("intensity_type") or st.get("intensity") or "").lower()}
    if "dist" in dtype:
        out["dist"] = _num(dval)
    else:
        out["d"] = _num(dval)
    tt = str(st.get("target_type") or "").lower()
    lo, hi = _num(st.get("target_value_min")), _num(st.get("target_value_max"))
    tg = st.get("targets")
    if isinstance(tg, list) and tg and isinstance(tg[0], dict):  # format v2
        t0 = tg[0]
        tt = str(t0.get("type") or "").lower()
        if tt == "zone":
            lo = hi = _num(t0.get("zone"))
            tt = "zone_" + str(t0.get("stream") or "")
        else:
            lo, hi = _num(t0.get("value")), _num(t0.get("value_max"))
            u = t0.get("unit")
            u = (u.get("untrusted_text") if isinstance(u, dict) else u) or ""
            tt = tt + "_" + str(u).lower()
    out["tt"], out["lo"], out["hi"] = tt, lo, hi
    return out


def fetch_planned(token, p, from_date, to_date):
    raw = nolio_get("get/planned/training/", token, p({"from": fmt(from_date), "to": fmt(to_date), "limit": 300})) or []
    out = []
    for pl in raw if isinstance(raw, list) else []:
        sw = pl.get("structured_workout")
        if sw and not DEBUG_PLANNED:
            DEBUG_PLANNED["sample"] = {"name": pl.get("name"), "structured_workout": sw}
        steps = []
        if isinstance(sw, list):
            steps = [x for x in (norm_plan_step(y) for y in sw) if x]
        elif isinstance(sw, dict) and isinstance(sw.get("steps"), list):
            steps = [x for x in (norm_plan_step(y) for y in sw["steps"]) if x]
        out.append({
            "date_start": pl.get("date_start"),
            "name": pl.get("name"),
            "sport": pl.get("sport"),
            "sport_id": pl.get("sport_id"),
            "duration": pl.get("duration"),
            "distance": pl.get("distance"),
            "rpe": pl.get("rpe"),
            "description": (pl.get("description") or "")[:600],
            "is_competition": pl.get("is_competition"),
            "plan": steps,
        })
    return out

# -- DONNEES D'UN COUREUR -----------------------------------------------------
def fetch_athlete(token, athlete_id, is_coach):
    now = datetime.now(timezone.utc)
    from_date = now - timedelta(days=DAYS_HISTORY)
    prev_from = from_date - timedelta(days=DAYS_PREV_30)

    def p(extra):
        if not is_coach:
            extra["athlete_id"] = athlete_id
        return extra

    trainings_90d = nolio_get("get/training/", token, p({"from": fmt(from_date), "to": fmt(now), "limit": 200})) or []
    trainings_prev = nolio_get("get/training/", token, p({"from": fmt(prev_from), "to": fmt(from_date), "limit": 100})) or []
    rmssd = nolio_get("get/hrv/rmssd/", token, p({"from": fmt(now - timedelta(days=30)), "to": fmt(now), "limit": 90})) or []
    pwr_records = nolio_get("get/records/", token, p({"cat": "ppr", "record_type": "time", "items": "180,300,720,1200"})) or []

    planned = fetch_planned(token, p, from_date, now + timedelta(days=14))

    sleep_daily = []
    meta = nolio_get("get/user/meta/", token, p({"from": fmt(now - timedelta(days=35)), "to": fmt(now), "limit": 60}))
    if meta and meta.get("sleep") and meta["sleep"].get("data"):
        def by_date(key, d):
            for s in (meta.get(key) or {}).get("data", []):
                if s.get("date") == d:
                    return s.get("value")
            return None
        for x in meta["sleep"]["data"]:
            if (x.get("value") or 0) > 0:
                d = x.get("date")
                sleep_daily.append({
                    "date": d, "hours": round(x["value"] / 3600, 2), "source": x.get("source"),
                    "score": by_date("sl_score", d), "deep": by_date("sl_deep", d),
                    "rem": by_date("sl_rem", d), "light": None
                })

    # FC repos = valeur du profil Nolio, reprise sur la seance la plus recente
    rest_hr = None
    if trainings_90d and trainings_90d[0].get("rest_hr_user"):
        rest_hr = trainings_90d[0]["rest_hr_user"]

    return {
        "trainings_90d": trainings_90d,
        "trainings_prev_30d": trainings_prev,
        "rmssd_30d": rmssd,
        "pwr_records": pwr_records,
        "sleep_daily": sleep_daily,
        "planned": planned,
        "rest_hr": rest_hr,
    }


def fmt(d):
    return d.strftime("%Y-%m-%d")


# -- MAIN ---------------------------------------------------------------------
def main():
    print("=" * 60)
    print("Nolio Sync (compte coach) - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 60)

    token = get_coach_token()

    roster = nolio_get("get/athletes/", token, {"wants_coach": "true"})
    if not roster:
        sys.exit("Impossible de recuperer la liste des coureurs (get/athletes).")
    print(str(len(roster)) + " personnes renvoyees par Nolio")

    all_team_names = sorted({t.get("name", "") for a in roster for t in (a.get("teams") or [])})
    print("Equipes vues : " + ", ".join(all_team_names))

    prev_resumes = load_previous_resumes()
    print(str(len(prev_resumes)) + " resumes de sorties deja calcules")

    result = []
    for a in roster:
        aid = str(a.get("nolio_id"))
        name = a.get("name", "?")
        is_coach = (aid == COACH_ID)
        codes = sorted({c for c in (team_code(t.get("name")) for t in (a.get("teams") or [])) if c})
        if is_coach and not codes:
            codes = ["NK"]
        if not codes:
            print("- " + name + " : aucune equipe NK/NMCA, ignore")
            continue

        print("- " + name + " (" + "+".join(codes) + ")")
        data = fetch_athlete(token, aid, is_coach)
        kept, new = add_resumes(data["trainings_90d"], prev_resumes)
        print("    resumes de sorties : " + str(kept) + " repris, " + str(new) + " nouveaux")
        print("    " + str(len(data["trainings_90d"])) + " seances | " + str(len(data["rmssd_30d"])) +
              " RMSSD | " + str(len(data["sleep_daily"])) + " nuits")

        # Une entree par equipe (le dashboard filtre sur team == equipe choisie)
        for c in codes:
            entry = {"athlete_id": aid, "name": name, "team": c,
                     "access_token": "", "refresh_token": "", "expires_at": "", "ai_summary": None}
            entry.update(data)
            result.append(entry)
        time.sleep(0.5)

    output = {"generated_at": datetime.now(timezone.utc).isoformat(), "athletes": result,
              "debug_planned_sample": DEBUG_PLANNED.get("sample")}
    out = json.dumps(output, ensure_ascii=False, separators=(",", ":"))
    enc = encrypt_json(out)
    print("\ndonnees : " + str(len(result)) + " fiches | " + str(len(out) // 1024) + " Ko -> chiffre " + str(len(enc) // 1024) + " Ko")

    print("Push GitHub (fichier chiffre)...")
    gh_write(ENC_FILE, enc, "sync: donnees chiffrees " + datetime.now().strftime("%Y-%m-%d %H:%M"))
    print("\nTermine - " + datetime.now().strftime("%H:%M:%S"))


if __name__ == "__main__":
    main()
