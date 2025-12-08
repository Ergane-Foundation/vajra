# Vajra: AI Based NGFW

  

> **Current Phase:** Hackathon Phase 1 (Architecture Design & Dataset Acquisition)

## 📖 Project Overview

Legacy firewalls are blind to modern threats. With **80% of web traffic now encrypted (TLS 1.3)** and the rise of IoT, static rules and simple signature matching are obsolete.

**Vajra** is a proposed Next-Generation Firewall (NGFW) designed for the **Zero Trust** era. It leverages **Deep Learning (1D-CNNs, Transformers)** and **Edge Computing (NVIDIA Jetson)** to inspect encrypted traffic *without decryption*, enforce micro-segmentation, and detect "Low & Slow" attacks that traditional IDS miss.

-----

## 🎯 Problem Statement

1.  **Encryption Blindness:** Traditional firewalls cannot see inside TLS 1.3 or QUIC packets without computationally expensive decryption.
2.  **Static Policies:** Rule-based systems fail against polymorphic malware and Zero-Day exploits.
3.  **IoT Vulnerability:** Edge devices lack the power to run heavy security agents, making them easy targets for botnets.

## 🛡️ Attack Coverage Strategy

We are designing the system to detect and mitigate the following specific threat vectors:

| Threat Vector | Attack Type | Detection Strategy |
| :--- | :--- | :--- |
| **Encrypted Malware** | C2 Communication over TLS 1.3 | **Encrypted Traffic Analysis (ETA)** using Metadata (Packet Timing/Size). |
| **DNS Tunneling** | Data Exfiltration & DGA | **NLP (Char-CNN)** on DNS query strings to detect non-human domains. |
| **IoT Botnets** | Mirai / DDoS Heartbeats | **Traffic Fingerprinting** to detect anomalous IoT device behavior. |
| **Insider Threats** | Lateral Movement | **Graph Neural Networks (GNN)** to map unauthorized internal connections. |
| **Evasion Techniques** | Tor / VPN Anonymizers | **Flow Analysis** to detect Darknet protocol signatures. |

-----

## 🧠 The AI Pipeline (Under Development)

Our architecture utilizes an **Ensemble Learning** approach, distributing tasks between the Data Plane (Fast) and Intelligence Plane (Deep).

### 1\. Fast-Path Classifiers (Edge / Data Plane)

  * **Goal:** Micro-second decision making.
  * **Model:** **Random Forest / XGBoost**.
  * **Function:** Device Fingerprinting (OS detection), Basic Protocol Validation.

### 2\. Deep Inspection Models (Intelligence Plane)

  * **Goal:** High-accuracy threat detection.
  * **Model:** **1D-CNN (Convolutional Neural Network)**.
      * *Input:* Sequence of Packet Lengths & Inter-Arrival Times.
      * *Task:* Classify malware in encrypted streams.
  * **Model:** **DistilBERT (Lightweight Transformer)**.
      * *Input:* HTTP Headers & Metadata.
      * *Task:* Detect malicious payloads and SQLi patterns in text protocols.

### 3\. Anomaly & Response

  * **Model:** **LSTM Autoencoder**.
      * *Task:* Zero Trust User Behavior Analytics (UEBA).
  * **Model:** **Federated Learning (FedAvg)**.
      * *Task:* Privacy-preserving model updates across distributed nodes.

-----

## 📊 Dataset Roadmap

We are currently aggregating and cleaning the following datasets to train our specialized models.

| Dataset Name | Source | Purpose in Sentinel-X | Status |
| :--- | :--- | :--- | :--- |
| **CIC-IDS-2017** | [Link](http://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/) | **Baseline Training.** Used for training Protocol Anomaly Detection (Brute Force, Port Scans). | ✅ Acquired |
| **CESNET-TLS22** | [GitHub](https://www.google.com/search?q=https://github.com/CESNET/inter-arrival-time-datasets) | **Encrypted Traffic Analysis.** Modern TLS 1.3 & QUIC traffic samples for training the 1D-CNN. | 🔄 Processing |
| **TON\_IoT** | [UNSW](https://research.unsw.edu.au/projects/toniot-datasets) | **IoT Security.** Telemetry from weather meters/thermostats mixed with attacks to train Edge models. | 🔄 Processing |
| **Stratosphere IPS** | [Link](https://www.stratosphereips.org/datasets-ctu13) | **Malware Behavior.** Real capture of Botnet traffic for C2 heartbeat detection. | ⏳ Planned |
| **CIC-Darknet2020** | [Link](https://www.unb.ca/cic/datasets/darknet2020.html) | **Anti-Evasion.** Traffic samples of Tor and VPNs to detect hidden channels. | ⏳ Planned |

-----

## 🛠️ Tech Stack & Architecture

  * **Hardware:** NVIDIA Jetson (Edge Inference).
  * **Data Plane:** eBPF / XDP (High-speed packet filtering).
  * **ML Frameworks:** PyTorch (Training), TensorRT (Inference Optimization), TensorFlow Federated.
  * **Feature Extraction:** Zeek (Bro), CICFlowMeter.

## 📅 Roadmap (Phase 1)

  - [x] Problem Statement Definition
  - [x] Architectural Design (Edge vs. Cloud split)
  - [ ] **Current Focus:** Data Ingestion & Feature Engineering (Packet -\> Vector)
  - [ ] **Next Step:** Training the initial 1D-CNN Prototype for Encrypted Traffic

-----

*Created for Smart India Hackathon by Sudarshana007.*