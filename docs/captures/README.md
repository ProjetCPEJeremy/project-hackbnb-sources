# Captures d'écran des exploitations

Preuves d'exploitation produites en laboratoire contre une instance faisant tourner le
**code-source original** de la plateforme (commit `3228940`), puis vérification contre
le **code corrigé**. Routes locales sans le préfixe `/api/` (ajouté par Apache en prod).

| Fichier | Défaut | Contenu |
|---------|--------|---------|
| `d1_sqli.png` | D1 | Injection SQL : contournement du filtre + `UNION SELECT` exfiltrant la table `users` |
| `d2_traversal.png` | D2 | Path traversal : lecture de `/etc/passwd`, `config.py`, puis vol de la base SQLite complète |
| `d3_ssrf.png` | D3 | Paramètre non contrôlé pilotant une requête serveur authentifiée vers Stripe (clé attachée) |
| `d4_secret.png` | D4 | Secret de confirmation prévisible : réservation confirmée **sans paiement** par brute-force |
| `d5_email.png` | D5 | Fuite de l'e-mail de l'hôte dans la réponse `/rooms/<id>` |
| `d6_gitsecret.png` | D6 | Clé API Stripe retrouvée dans l'historique Git |
| `d8_headers.png` | D7/D8 | En-tête `Server` divulgué + mode debug Werkzeug actif (console RCE) |
| `fix_verification.png` | — | Vérification : attaques D1/D2/D3/D5/D8 bloquées sur le code corrigé |
| `fix_verification2.png` | — | Vérification : D3 (session rejetée) et D4 (brute-force inutile) sur le code corrigé |

> Note : pour D7, la XSS stockée repose sur le rendu de `room.description` via
> `dangerouslySetInnerHTML` (`front/src/pages/room/Room.tsx:52`) combiné à l'absence de CSP.
> Une capture d'exécution dans le navigateur peut être ajoutée en injectant une description
> contenant `<img src=x onerror=alert(document.domain)>`.
