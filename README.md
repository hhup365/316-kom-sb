# EdgeSync Connect (ESC-Core)

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com)
[![Platform](https://img.shields.io/badge/platform-docker%20%7C%20k8s-blue)](https://github.com)
[![License](https://img.shields.io/badge/license-MIT-grey)](https://github.com)

**EdgeSync Connect** is a high-performance, zero-dependency network middleware designed for secure edge-to-cloud data synchronization. It orchestrates multiple transport protocols to ensure reliable connectivity in complex network environments. Built for containerized deployments (Docker/Kubernetes) with automated self-healing capabilities.

## 🚀 Quick Start (Docker)

Deploy the service with minimal configuration using the pre-built Alpine image.

```bash
docker run -d \
  --name edgesync-node \
  --restart always \
  --network host \
  -e WEBPT=3000 \
  -e RSPT=443 \
  -e PNAME="US-West-Gateway" \
  edgesync-service:latest
```

## ⚙️ Configuration Reference

The application is configured entirely via Environment Variables (`ENV`).

### 1. System & Management

| Variable | Default | Description |
| :--- | :--- | :--- |
| `WEBPT` | `3000` | **Management Port**. Used for health checks and API access. |
| `PNAME` | `ABC` | **Instance Tag**. Identifier for the node in the cluster dashboard. |
| `DATA_PATH` | `./sbata` | **Volume Path**. Persistence directory for logs and security keys. |
| `LINK_PATH` | `/api/data` | **Discovery Endpoint**. Path to retrieve the node's connection metadata. |

### 2. Transport Protocols (Channels)

Define the ports and credentials for data ingress. **Leave empty to disable a specific protocol.**

| Variable | Protocol Ref | Port | ID/User Token | Secret/Key | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Vision** | *R* | `RSPT` | `RUDPS` | *(Auto)* | **Primary Stream**. Uses TLS fingerprinting simulation for high stealth. |
| **Hyper** | *H* | `HSPT` | - | `HSPS` | **UDP Accelerator**. Optimized for high-latency, lossy networks. |
| **Turbo** | *Tc* | `TSPT` | `TUDPS` | `TSPS` | **Multiplex Stream**. Low-overhead 0-RTT transport channel. |
| **Adaptive** | *A* | `ASPT` | `AUDPS` | - | **Fallback TLS**. Standard secure transport for compatibility. |
| **Legacy** | *S* | `SSPT` | `SSNAME` | `SSPS` | **Standard Socket**. Basic proxy interface for legacy apps. |

> **Note**: If credentials (`RUDPS`, `HSPS`, etc.) are not provided, the system will auto-generate strong random keys upon initialization.

### 3. Network Routing & Peering

Configure how the node announces itself and handles handshake verification.

| Variable | Example | Description |
| :--- | :--- | :--- |
| `RSIN` | `` | **SNI Indicator**. The Server Name Indication used for Vision handshake verification. |
| `RDEST` | ``| **Upstream Target**. The destination for traffic fallback (decoy traffic). |
| `CERDN` | `example.com` | **Service Domain**. The DNS name associated with the SSL certificate. |
| `SBFS` | `false` | **Traffic Shaping**. Set to `true` to enable advanced jitter/obfuscation on the Hyper channel. |
| `HSBPS` | - | **Shaping Key**. Required if `SBFS` is enabled. |

### 4. Security & Certificate Provisioning

ESC-Core supports automated certificate lifecycle management via remote fetching or local generation.

| Variable | Description |
| :--- | :--- |
| `CERURL` | **Remote Certificate URL** (CRT/PEM). |
| `KEYURL` | **Remote Private Key URL** (KEY). |

**Provisioning Logic:**
1.  **Remote Fetch**: Attempts to download credentials from the provided URLs.
2.  **Local Cache**: Checks `DATA_PATH` for existing valid keys.
3.  **Self-Healing**: If no valid certificates are found, the system utilizes **OpenSSL** to generate a compliant RSA-2048 self-signed certificate (`CN=www.bing.com`) valid for 100 years to ensure service continuity.

### 5. Sidecar Integration (Optional)

| Variable | Description |
| :--- | :--- |
| `KMHOST` | **Key Manager Host**. Address of the external authentication sidecar. |
| `KMAUTH` | **Auth Token**. Bearer token for the sidecar connection. |

---

## 📡 API Endpoints

*   **`GET /`**: Health status and version info.
*   **`GET <LINK_PATH>`**: (Default `/api/data`) Returns the base64-encoded configuration blob for client synchronization.
*   **`GET /api/re`**: **Hot Reload**. Triggers a configuration refresh and certificate rotation without dropping active connections.

## ⚠️ Disclaimer

This software is intended for **internal network infrastructure management**, **load testing**, and **authorized data synchronization** only. The developers assume no liability for misuse or deployment in unauthorized network environments.
