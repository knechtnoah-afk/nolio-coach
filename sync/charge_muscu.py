# -*- coding: utf-8 -*-
"""Charge Coggan des seances de musculation / renforcement realisees : 50 par heure.

Convention du coach (18/11/2026) : la charge Coggan (TSS) d'une seance de muscu vaut
50 par heure de seance. Les UA Foster (duree x RPE) ne sont pas touchees.
Ne remplace jamais une valeur deja renseignee (traitement precedent ou saisie du coach).

Utilise l'API Nolio v2 avec la cle personnelle du coach (secret GitHub NOLIO_API_KEY).
Sans cle, le script ne fait rien et ne bloque pas la synchro.
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

API = "https://www.nolio.io/api/v2/"
SPORTS_MUSCU = {"spt_vxmhSsLPpMbXD21", "spt_l5JdauYgoPxMr3b"}  # Musculation, Renforcement musculaire
TSS_PAR_HEURE = 50
JOURS = 4


def appel(methode, chemin, cle, params=None, corps=None):
    url = API + chemin + ("?" + urlencode(params) if params else "")
    data = json.dumps(corps).encode() if corps is not None else None
    req = Request(url, data=data, method=methode, headers={
        "Authorization": "Bearer " + cle, "Accept": "application/json",
        "Content-Type": "application/json", "User-Agent": "nolio-coach-sync"})
    try:
        with urlopen(req, timeout=60) as r:
            brut = r.read()
            return (json.loads(brut) if brut else None), None
    except HTTPError as e:
        return None, "HTTP %s %s" % (e.code, e.read().decode("utf-8", "ignore")[:200])
    except Exception as e:  # reseau
        return None, str(e)[:200]


def liste(chemin, cle, params):
    out, apres = [], None
    for _ in range(20):
        p = dict(params, limit=100)
        if apres:
            p["starting_after"] = apres
        res, err = appel("GET", chemin, cle, p)
        if err:
            return out, err
        lignes = (res or {}).get("data") or []
        out += lignes
        if not (res or {}).get("has_more") or not lignes:
            break
        apres = lignes[-1].get("id")
    return out, None


def texte(v):
    return (v.get("untrusted_text") if isinstance(v, dict) else v) or ""


def main():
    cle = os.environ.get("NOLIO_API_KEY", "").strip()
    if not cle:
        print("Charge muscu : pas de cle NOLIO_API_KEY, etape ignoree.")
        return 0
    fin = datetime.now(timezone.utc).date()
    debut = fin - timedelta(days=JOURS)
    coureurs, err = liste("me/athletes/", cle, {})
    if err:
        print("Charge muscu : lecture des coureurs impossible (" + err + ")")
        return 0
    faits, deja, erreurs = [], 0, []
    for c in coureurs:
        uid, nom = c.get("id"), texte(c.get("name"))
        seances, err = liste("real/trainings/", cle, {
            "athlete": uid, "date_from": debut.isoformat(), "date_to": fin.isoformat(),
            "fields": "sport,date_start,duration,coggan_load"})
        if err:
            erreurs.append(nom + " : " + err[:80])
            continue
        for s in seances:
            if s.get("sport") not in SPORTS_MUSCU:
                continue
            if s.get("coggan_load") is not None:
                deja += 1
                continue
            duree = ((s.get("duration") or {}).get("value") or 0) / 3600.0
            cible = max(1, int(round(TSS_PAR_HEURE * duree))) if duree else TSS_PAR_HEURE
            _, err = appel("PATCH", "real/trainings/%s/" % s["id"], cle, {"athlete": uid}, {"coggan_load": cible})
            if err:
                erreurs.append("%s %s : %s" % (nom, s.get("date_start"), err[:80]))
            else:
                faits.append("%s %s -> %d" % (nom, s.get("date_start"), cible))
    print("Charge muscu (%s au %s) : %d seance(s) mise(s) a jour, %d deja renseignee(s), %d erreur(s)"
          % (debut, fin, len(faits), deja, len(erreurs)))
    for f in faits:
        print("  + " + f)
    for e in erreurs:
        print("  ! " + e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
