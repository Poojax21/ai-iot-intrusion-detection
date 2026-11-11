# Pahredaar-IoT — Label Normalization & Taxonomy
**Document Version:** 2.0  
**Authority:** `training/preprocessing/label_normalizer.py`  

---

## 1. Centralized Taxonomy Overview

Public IoT datasets use inconsistent, highly idiosyncratic labeling conventions (e.g. `PartOfAHorizontalPortScan`, `DDoS-UDP_Flood`, `password`, `normal`, `BenignTraffic`). 

Pahredaar-IoT maps all incoming labels into an 8-class standard taxonomy while strictly preserving the original raw string, attack category, and provenance:

```text
Normalized Classes:
  ├── BENIGN          (Legitimate device communication)
  ├── PORT_SCAN       (Horizontal/vertical scans, host discovery, OS fingerprinting)
  ├── DDOS            (Distributed denial of service floods)
  ├── BRUTE_FORCE     (Credential access, Telnet/SSH dictionary attacks)
  ├── BOTNET          (Generic botnet C2, recruitment, infected node commands)
  ├── MIRAI_BEACON    (Periodic C2 heartbeats, Mirai-specific beaconing)
  ├── OTHER_ATTACK    (DoS, Web SQLi/XSS, Ransomware, MITM ARP/DNS spoofing)
  └── UNKNOWN         (Unmapped or zero-day anomalous patterns)
```

---

## 2. Dataset-Specific Mapping Rules

### IoT-23
| Original Label | Normalized Label | Attack Category | Confidence |
|---|---|---|---|
| `Benign` / `-` | `BENIGN` | `benign` | 1.0 |
| `PartOfAHorizontalPortScan` | `PORT_SCAN` | `reconnaissance` | 1.0 |
| `DDoS` | `DDOS` | `denial_of_service` | 1.0 |
| `C&C` / `Okiru` / `Torii` | `BOTNET` | `botnet_c2` | 0.95 |
| `C&C-HeartBeat` / `Mirai` | `MIRAI_BEACON` | `beaconing` | 0.95 |
| `Attack` / `C&C-FileDownload` | `OTHER_ATTACK` | `generic_attack` | 0.85 |

### CICIoT2023
| Original Label | Normalized Label | Attack Category | Confidence |
|---|---|---|---|
| `BenignTraffic` | `BENIGN` | `benign` | 1.0 |
| `Recon-PortScan` / `Recon-OSScan` / `Recon-HostDiscovery` | `PORT_SCAN` | `reconnaissance` | 1.0 |
| `DDoS-UDP_Flood` / `DDoS-TCP_Flood` / `DDoS-SYN_Flood` | `DDOS` | `denial_of_service` | 1.0 |
| `DictionaryBruteForce` | `BRUTE_FORCE` | `credential_access` | 1.0 |
| `Mirai-greeth_flood` / `Mirai-greip_flood` / `Mirai-udpplain` | `MIRAI_BEACON` | `mirai_flood` | 0.95 |
| `MITM-ArpSpoofing` / `DNS_Spoofing` | `OTHER_ATTACK` | `spoofing` | 0.95 |
| `SqlInjection` / `CommandInjection` / `XSS` | `OTHER_ATTACK` | `web_exploit` | 0.95 |
| `DoS-UDP_Flood` / `DoS-TCP_Flood` | `OTHER_ATTACK` | `denial_of_service_dos` | 0.95 |

### TON_IoT (Network)
| Original Label (`type`) | Normalized Label | Attack Category | Confidence |
|---|---|---|---|
| `normal` | `BENIGN` | `benign` | 1.0 |
| `scanning` | `PORT_SCAN` | `reconnaissance` | 1.0 |
| `ddos` | `DDOS` | `denial_of_service` | 1.0 |
| `password` | `BRUTE_FORCE` | `credential_access` | 1.0 |
| `dos` | `OTHER_ATTACK` | `denial_of_service_dos` | 0.90 |
| `ransomware` / `backdoor` | `OTHER_ATTACK` | `malware` | 0.95 |
| `injection` / `xss` | `OTHER_ATTACK` | `web_exploit` | 0.95 |

---

## 3. Anti-Conflation Principles

1. **DoS $\ne$ DDoS:** Single-source DoS attacks are labeled `OTHER_ATTACK` with category `denial_of_service_dos`, preventing false inflation of distributed flood detectors.
2. **Generic Botnet $\ne$ Mirai Beacon:** Generic C2 activity is isolated into `BOTNET`; only specific periodic beacons or verified Mirai floods receive `MIRAI_BEACON`.
3. **No Forced Guesses:** If a label is not known with high confidence, it maps to `UNKNOWN` rather than receiving a false positive label.
