# 🛡️ Mini IDS Réseau

Un **Intrusion Detection System (IDS)** développé en Python permettant de :
- capturer ou simuler du trafic réseau
- détecter des comportements suspects
- générer des alertes avec scoring
- visualiser les événements dans un dashboard web

---

## 🚀 Fonctionnalités

### 🔍 Analyse réseau
- Extraction des paquets (IP, ports, protocole)
- Simulation de trafic malveillant
- Détection en temps réel

### ⚠️ Détection d’attaques
- Scan de ports
- Flood (volume anormal de paquets)
- Analyse comportementale

### 📊 Dashboard
- Vue en temps réel des alertes
- Score de sévérité
- Historique des événements
- Export rapport TXT

---

## 🧠 Objectif du projet

Ce projet simule le fonctionnement d’un IDS simplifié utilisé en cybersécurité pour :
- identifier des comportements suspects
- transformer du trafic brut en alertes exploitables
- fournir une vision claire via un dashboard

---

## 🏗️ Architecture
ids-project/
├── app/
│ ├── main.py
│ ├── detector.py
│ ├── sniffer.py
│ ├── simulator.py
│ ├── database.py
│ ├── models.py
│ ├── schemas.py
│ ├── utils.py
│ ├── templates/
│ │ └── dashboard.html
│ └── static/
│ └── style.css
├── requirements.txt
└── README.md


## ⚙️ Installation

bash
git clone https://github.com/TON_USERNAME/mini-ids.git
cd mini-ids

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

▶️ Lancement
▶️ Lancement
python -m uvicorn app.main:app --reload

Accès :

Dashboard → http://127.0.0.1:8000
API docs → http://127.0.0.1:8000/docs

Tests (simulation)
Scan de ports
curl -X POST http://127.0.0.1:8000/simulate \
-H "Content-Type: application/json" \
-d '{"kind":"port_scan","src_ip":"192.168.1.50","dst_ip":"192.168.1.10","count":20}'
Flood
curl -X POST http://127.0.0.1:8000/simulate \
-H "Content-Type: application/json" \
-d '{"kind":"flood","src_ip":"10.0.0.8","dst_ip":"192.168.1.10","count":100}'
📈 Exemple de détection
Scan de ports → score élevé (critical)
Flood réseau → alerte de volume anormal
Classification automatique des événements

🧑‍💻 Technologies utilisées
Python
FastAPI
Scapy
SQLite
Jinja2

🎯 Ce que démontre ce projet
Analyse réseau
Détection d’intrusion
Traitement de données en temps réel
Conception d’un outil cybersécurité complet

📌 Améliorations possibles
Corrélation avancée d’événements
Score de menace par IP
Visualisation temps réel (WebSocket)
Intégration SIEM
Machine Learning pour détection avancée
