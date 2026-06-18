<p align="center">

<img src="https://img.shields.io/github/stars/cyphern0x/NetWatch?style=for-the-badge" alt="Stars">
<img src="https://img.shields.io/github/forks/cyphern0x/NetWatch?style=for-the-badge" alt="Forks">
<img src="https://img.shields.io/github/issues/cyphern0x/NetWatch?style=for-the-badge" alt="Issues">
<img src="https://img.shields.io/github/last-commit/cyphern0x/NetWatch?style=for-the-badge" alt="Last Commit">

<br><br>

<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
<img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/FastAPI-0.115.6-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
<img src="https://img.shields.io/badge/Scapy-2.6.1-orange?style=for-the-badge" alt="Scapy">
<img src="https://img.shields.io/badge/Uvicorn-0.34.0-4051B5?style=for-the-badge" alt="Uvicorn">
<img src="https://img.shields.io/badge/PyInstaller-6.15+-E6522C?style=for-the-badge" alt="PyInstaller">

</p>

<h1 align="center">NetWatch</h1>

<p align="center">
Real-Time Network Monitoring, Device Discovery and Intrusion Awareness Platform
</p>

<p align="center">
Built with Python, FastAPI, Scapy, Uvicorn and Tkinter
</p>

<p align="center">
<a href="https://github.com/cyphern0x/NetWatch">Repository</a> •
<a href="#features">Features</a> •
<a href="#api-endpoints">API</a> •
<a href="#installation">Installation</a> •
<a href="#license">License</a>
</p>
<p align="center">

<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
<img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/FastAPI-0.115.6-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
<img src="https://img.shields.io/badge/Scapy-2.6.1-orange?style=for-the-badge" alt="Scapy">
<img src="https://img.shields.io/badge/Uvicorn-0.34.0-4051B5?style=for-the-badge" alt="Uvicorn">
<img src="https://img.shields.io/badge/PyInstaller-6.15+-E6522C?style=for-the-badge" alt="PyInstaller">

</p>

<h1 align="center">NetWatch</h1>

<p align="center">
Real-Time Network Monitoring, Device Discovery and Intrusion Awareness Platform
</p>

<p align="center">
Built with FastAPI, Scapy and Python
</p>

---

## Languages

* [Türkçe](#türkçe)
* [English](#english)

---

## Table of Contents

* Overview
* Features
* Technology Stack
* Dependencies
* Installation
* Configuration
* API Endpoints
* Usage
* Project Structure
* Security Notice
* Roadmap
* License

---

# Türkçe

## Genel Bakış

NetWatch, yerel ağları gerçek zamanlı olarak izlemek, bağlı cihazları keşfetmek ve yeni cihazları algılamak için geliştirilmiş modern bir ağ izleme platformudur.

Sistem ARP tabanlı ağ keşfi gerçekleştirir, cihaz geçmişini saklar, yeni cihazları tespit eder, uyarılar üretir ve tüm verileri FastAPI üzerinden REST API olarak sunar.

Ayrıca masaüstü arayüzü, Windows Firewall entegrasyonu ve tek dosya EXE oluşturma desteği içerir.

---

## Özellikler

### Ağ Keşfi

* ARP tabanlı ağ tarama
* Yerel ağ cihaz keşfi
* IP adresi tespiti
* MAC adresi tespiti
* Hostname çözümleme
* Vendor (Üretici) tespiti

### Cihaz Analizi

* Router tespiti
* Gateway tespiti
* IoT cihaz sınıflandırması
* Sanal makine tespiti
* Bilgisayar tespiti
* Mobil cihaz analizi

### İzleme

* Gerçek zamanlı ağ izleme
* Otomatik tarama döngüsü
* Manuel tarama
* Baseline oluşturma
* Geçmiş kayıtları
* Sürekli cihaz takibi

### Uyarı Sistemi

* Yeni cihaz tespiti
* Şüpheli cihaz farkındalığı
* Uyarı geçmişi
* Kalıcı kayıt sistemi

### Güvenlik

* Windows Firewall entegrasyonu
* IP engelleme
* IP engel kaldırma
* Yerel ağ kontrolü

### Masaüstü Arayüzü

* Tkinter GUI
* Cihaz tablosu
* Uyarı paneli
* Manuel tarama
* Baseline sıfırlama

---

## Teknoloji Yığını

| Teknoloji     | Sürüm   |
| ------------- | ------- |
| Python        | 3.11+   |
| FastAPI       | 0.115.6 |
| Scapy         | 2.6.1   |
| Uvicorn       | 0.34.0  |
| python-dotenv | 1.0.1   |
| PyInstaller   | 6.15+   |

---

## Bağımlılıklar

```txt
fastapi==0.115.6
uvicorn[standard]==0.34.0
scapy==2.6.1
python-dotenv==1.0.1
pyinstaller>=6.15.0,<7.0.0
```

---

## Kurulum

### Depoyu Klonlayın

```bash
git clone https://github.com/cyphern0x/NetWatch.git
cd NetWatch
```

### Sanal Ortam Oluşturun

```bash
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

Linux:

```bash
source venv/bin/activate
```

### Bağımlılıkları Kurun

```bash
pip install -r requirements.txt
```

---

## Yapılandırma

`.env`

```env
NETWATCH_API_HOST=0.0.0.0
NETWATCH_API_PORT=8000
NETWATCH_SCAN_INTERVAL=60
NETWATCH_NETWORK_CIDR=192.168.1.0/24
NETWATCH_INTERFACE=
```

---

## API Endpointleri

### Cihazlar

```http
GET /devices
```

### Uyarılar

```http
GET /alerts
```

### Sağlık Kontrolü

```http
GET /health
```

### Manuel Tarama

```http
POST /scan
```

### Baseline Sıfırlama

```http
POST /reset
```

### IP Engelleme

```http
POST /devices/{ip}/block
```

### IP Engel Kaldırma

```http
POST /devices/{ip}/unblock
```

---

## Çalıştırma

API Modu:

```bash
python main.py --api-only
```

Masaüstü Arayüzü:

```bash
python main.py
```

EXE Oluşturma:

```bash
python main.py --build-exe
```

Backend EXE:

```bash
python main.py --build-backend-exe
```

---

## Proje Yapısı

```text
NetWatch/
│
├── main.py
├── requirements.txt
├── .env
├── .env.example
├── netwatch_history.json
│
├── build/
├── dist/
│
└── README.md
```

---

## Yol Haritası

* Web Dashboard
* Docker Desteği
* PDF Raporlama
* Prometheus Entegrasyonu
* Grafana Entegrasyonu
* Çoklu Ağ Desteği
* Gelişmiş Tehdit Analizi
* Ağ Haritalama

---

## Güvenlik Bildirimi

NetWatch yalnızca yetkili ağlarda kullanılmalıdır.

Kullanıcılar yürürlükteki yasa ve düzenlemelere uymaktan sorumludur.

---

# English

## Overview

NetWatch is a real-time network monitoring and device discovery platform designed to identify, classify and monitor devices connected to local networks.

The system performs ARP-based discovery, maintains a device baseline, detects new devices, generates alerts and exposes all monitoring data through a FastAPI-powered REST API.

It also includes a desktop interface, Windows Firewall integration and standalone executable generation support.

---

## Features

* ARP Network Discovery
* Device Detection
* Vendor Identification
* Hostname Resolution
* Device Classification
* Real-Time Monitoring
* Alert Generation
* Device Baseline Tracking
* History Persistence
* REST API
* Tkinter Desktop Interface
* Windows Firewall Integration
* Device Blocking & Unblocking
* EXE Build Support

---

## Installation

```bash
git clone https://github.com/cyphern0x/NetWatch.git
cd NetWatch
pip install -r requirements.txt
```

---

## Run

API Only:

```bash
python main.py --api-only
```

Desktop Application:

```bash
python main.py
```

Build EXE:

```bash
python main.py --build-exe
```

---

## Author

Cyphern0x

Network Monitoring • FastAPI • Scapy • Security Automation

---

## License

Released under the MIT License.
