# Dataset Audit Report: TON_IOT

- **Generated At:** 2026-11-11T08:02:27.497125+00:00
- **Source:** `tests\fixtures\sample_ton_iot.csv`
- **Total Flow Records:** 5
- **Capture Span:** 0.0 hours (`1554130000.1` to `1554130004.5`)

## 1. Class Distribution

| Normalized Class | Flow Count | Percentage |
|---|---|---|
| `BENIGN` | 1 | 20.0% |
| `PORT_SCAN` | 1 | 20.0% |
| `DDOS` | 1 | 20.0% |
| `BRUTE_FORCE` | 1 | 20.0% |
| `OTHER_ATTACK` | 1 | 20.0% |

- **Class Imbalance Ratio:** 1.0:1
- **Shannon Diversity Entropy:** 2.3219 bits

## 2. Feature Compatibility vs. Canonical Contract (V1)

- **Compatibility Score:** 80.0%
- **Fully Compatible:** ⚠️ PARTIAL

### Breakdown:
- **Directly Compatible (1):** duration
- **Derivable (15):** total_bytes, total_pkts, byte_rate, pkt_rate, avg_pkt_size, is_new_edge, src_fanout_recent, device_zscore, proto_tcp, proto_udp, proto_icmp, conn_state_sf, conn_state_s0, conn_state_rej, conn_state_other
- **Unavailable (4):** orig_bytes, resp_bytes, orig_pkts, resp_pkts
