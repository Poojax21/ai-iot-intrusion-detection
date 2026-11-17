"""
Centralized Label Normalization Module.

Maps diverse public dataset labels (IoT-23, CICIoT2023, TON_IoT) into a standardized
hierarchical attack taxonomy while strictly preserving original strings and categories.

Standardized top-level classes:
  - BENIGN
  - PORT_SCAN
  - DDOS
  - BRUTE_FORCE
  - BOTNET
  - MIRAI_BEACON
  - OTHER_ATTACK
  - UNKNOWN
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class NormalizedLabel(str, Enum):
    BENIGN = "BENIGN"
    PORT_SCAN = "PORT_SCAN"
    DDOS = "DDOS"
    BRUTE_FORCE = "BRUTE_FORCE"
    BOTNET = "BOTNET"
    MIRAI_BEACON = "MIRAI_BEACON"
    OTHER_ATTACK = "OTHER_ATTACK"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class LabelMappingResult:
    original_label: str
    normalized_label: NormalizedLabel
    attack_category: str
    dataset_name: str
    confidence: float
    is_attack: bool


class LabelNormalizer:
    """Rules-based and keyword-driven normalizer preserving ground-truth provenance."""

    def __init__(self):
        # Explicit full-string mappings for known exact dataset outputs
        self._exact_rules: Dict[Tuple[str, str], Tuple[NormalizedLabel, str, float]] = {}
        self._init_exact_rules()

    def _init_exact_rules(self):
        # -------------------------------------------------------------
        # IoT-23 Exact Labels
        # -------------------------------------------------------------
        iot23_exact = {
            "benign": (NormalizedLabel.BENIGN, "benign", 1.0),
            "-   benign   -": (NormalizedLabel.BENIGN, "benign", 1.0),
            "(empty)   benign   -": (NormalizedLabel.BENIGN, "benign", 1.0),
            "partofahorizontalportscan": (NormalizedLabel.PORT_SCAN, "reconnaissance", 1.0),
            "malicious   partofahorizontalportscan": (NormalizedLabel.PORT_SCAN, "reconnaissance", 1.0),
            "c&c": (NormalizedLabel.BOTNET, "c2", 0.95),
            "malicious   c&c": (NormalizedLabel.BOTNET, "c2", 0.95),
            "c&c-heartbeat": (NormalizedLabel.MIRAI_BEACON, "beaconing", 0.95),
            "malicious   c&c-heartbeat": (NormalizedLabel.MIRAI_BEACON, "beaconing", 0.95),
            "c&c-torii": (NormalizedLabel.BOTNET, "c2", 0.95),
            "c&c-mirai": (NormalizedLabel.MIRAI_BEACON, "beaconing", 0.95),
            "ddos": (NormalizedLabel.DDOS, "denial_of_service", 1.0),
            "malicious   ddos": (NormalizedLabel.DDOS, "denial_of_service", 1.0),
            "attack": (NormalizedLabel.OTHER_ATTACK, "generic_attack", 0.8),
            "malicious   attack": (NormalizedLabel.OTHER_ATTACK, "generic_attack", 0.8),
            "okiru": (NormalizedLabel.BOTNET, "botnet_infection", 0.9),
            "malicious   okiru": (NormalizedLabel.BOTNET, "botnet_infection", 0.9),
            "c&c-filedownload": (NormalizedLabel.OTHER_ATTACK, "payload_delivery", 0.9),
        }
        for k, v in iot23_exact.items():
            self._exact_rules[("iot23", k)] = v

        # -------------------------------------------------------------
        # CICIoT2023 Exact Labels
        # -------------------------------------------------------------
        ciciot_exact = {
            "benigntraffic": (NormalizedLabel.BENIGN, "benign", 1.0),
            "dictionarybruteforce": (NormalizedLabel.BRUTE_FORCE, "credential_access", 1.0),
            "recon-portscan": (NormalizedLabel.PORT_SCAN, "reconnaissance", 1.0),
            "recon-osscan": (NormalizedLabel.PORT_SCAN, "reconnaissance", 0.95),
            "recon-hostdiscovery": (NormalizedLabel.PORT_SCAN, "reconnaissance", 0.95),
            "recon-pingsweep": (NormalizedLabel.PORT_SCAN, "reconnaissance", 0.95),
            "vulnerabilityscan": (NormalizedLabel.PORT_SCAN, "vulnerability_scan", 0.95),
            # Specific Mirai variants
            "mirai-greeth_flood": (NormalizedLabel.MIRAI_BEACON, "mirai_flood", 0.95),
            "mirai-greip_flood": (NormalizedLabel.MIRAI_BEACON, "mirai_flood", 0.95),
            "mirai-udpplain": (NormalizedLabel.MIRAI_BEACON, "mirai_flood", 0.95),
            # Spoofing & Web (mapped cleanly to OTHER_ATTACK preserving category)
            "mitm-arpspoofing": (NormalizedLabel.OTHER_ATTACK, "spoofing_arp", 0.95),
            "dns_spoofing": (NormalizedLabel.OTHER_ATTACK, "spoofing_dns", 0.95),
            "sqlinjection": (NormalizedLabel.OTHER_ATTACK, "web_sqli", 0.95),
            "commandinjection": (NormalizedLabel.OTHER_ATTACK, "web_cmdi", 0.95),
            "xss": (NormalizedLabel.OTHER_ATTACK, "web_xss", 0.95),
            "backdoor_malware": (NormalizedLabel.OTHER_ATTACK, "backdoor", 0.95),
            "uploading_attack": (NormalizedLabel.OTHER_ATTACK, "web_upload", 0.95),
            "browserhijacking": (NormalizedLabel.OTHER_ATTACK, "browser_hijack", 0.95),
        }
        for k, v in ciciot_exact.items():
            self._exact_rules[("ciciot2023", k)] = v

        # -------------------------------------------------------------
        # TON_IoT Exact Labels
        # -------------------------------------------------------------
        ton_exact = {
            "normal": (NormalizedLabel.BENIGN, "benign", 1.0),
            "scanning": (NormalizedLabel.PORT_SCAN, "reconnaissance", 1.0),
            "password": (NormalizedLabel.BRUTE_FORCE, "credential_access", 1.0),
            "ddos": (NormalizedLabel.DDOS, "denial_of_service", 1.0),
            "dos": (NormalizedLabel.OTHER_ATTACK, "denial_of_service_dos", 0.9),
            "ransomware": (NormalizedLabel.OTHER_ATTACK, "malware_ransomware", 0.95),
            "backdoor": (NormalizedLabel.OTHER_ATTACK, "malware_backdoor", 0.95),
            "injection": (NormalizedLabel.OTHER_ATTACK, "web_injection", 0.95),
            "xss": (NormalizedLabel.OTHER_ATTACK, "web_xss", 0.95),
            "mitm": (NormalizedLabel.OTHER_ATTACK, "mitm", 0.95),
        }
        for k, v in ton_exact.items():
            self._exact_rules[("ton_iot", k)] = v

        # -------------------------------------------------------------
        # Bot-IoT Exact Labels
        # -------------------------------------------------------------
        bot_iot_exact = {
            "normal": (NormalizedLabel.BENIGN, "benign", 1.0),
            "normal_normal": (NormalizedLabel.BENIGN, "benign", 1.0),
            "ddos": (NormalizedLabel.DDOS, "denial_of_service", 1.0),
            "ddos_tcp": (NormalizedLabel.DDOS, "denial_of_service", 1.0),
            "ddos_udp": (NormalizedLabel.DDOS, "denial_of_service", 1.0),
            "ddos_http": (NormalizedLabel.DDOS, "denial_of_service", 1.0),
            "dos": (NormalizedLabel.OTHER_ATTACK, "denial_of_service_dos", 0.95),
            "dos_tcp": (NormalizedLabel.OTHER_ATTACK, "denial_of_service_dos", 0.95),
            "dos_udp": (NormalizedLabel.OTHER_ATTACK, "denial_of_service_dos", 0.95),
            "dos_http": (NormalizedLabel.OTHER_ATTACK, "denial_of_service_dos", 0.95),
            "reconnaissance": (NormalizedLabel.PORT_SCAN, "reconnaissance", 1.0),
            "reconnaissance_os_fingerprint": (NormalizedLabel.PORT_SCAN, "reconnaissance", 0.95),
            "reconnaissance_service_scan": (NormalizedLabel.PORT_SCAN, "reconnaissance", 1.0),
            "theft": (NormalizedLabel.OTHER_ATTACK, "data_exfiltration", 0.95),
            "theft_keylogging": (NormalizedLabel.OTHER_ATTACK, "keylogging", 0.95),
            "theft_data_exfiltration": (NormalizedLabel.OTHER_ATTACK, "data_exfiltration", 0.95),
        }
        for k, v in bot_iot_exact.items():
            self._exact_rules[("bot_iot", k)] = v

        # -------------------------------------------------------------
        # N-BaIoT Exact Labels
        # -------------------------------------------------------------
        nbaiot_exact = {
            "benign": (NormalizedLabel.BENIGN, "benign", 1.0),
            "mirai": (NormalizedLabel.BOTNET, "botnet_infection", 0.95),
            "gafgyt": (NormalizedLabel.BOTNET, "botnet_infection", 0.95),
            "mirai_scan": (NormalizedLabel.PORT_SCAN, "reconnaissance", 0.95),
            "gafgyt_scan": (NormalizedLabel.PORT_SCAN, "reconnaissance", 0.95),
            "mirai_syn": (NormalizedLabel.DDOS, "denial_of_service", 0.95),
            "mirai_ack": (NormalizedLabel.DDOS, "denial_of_service", 0.95),
            "mirai_udp": (NormalizedLabel.DDOS, "denial_of_service", 0.95),
            "gafgyt_combo": (NormalizedLabel.BOTNET, "c2_combo", 0.95),
            "gafgyt_junk": (NormalizedLabel.BOTNET, "botnet_traffic", 0.95),
        }
        for k, v in nbaiot_exact.items():
            self._exact_rules[("nbaiot", k)] = v

        # -------------------------------------------------------------
        # Edge-IIoTset Exact Labels (IEEE 2022)
        # -------------------------------------------------------------
        edge_iiotset_exact = {
            "normal": (NormalizedLabel.BENIGN, "benign", 1.0),
            "ddos_udp": (NormalizedLabel.DDOS, "denial_of_service", 1.0),
            "ddos_icmp": (NormalizedLabel.DDOS, "denial_of_service", 1.0),
            "ddos_http": (NormalizedLabel.DDOS, "denial_of_service", 1.0),
            "ddos_tcp": (NormalizedLabel.DDOS, "denial_of_service", 1.0),
            "port_scanning": (NormalizedLabel.PORT_SCAN, "reconnaissance", 1.0),
            "vulnerability_scanner": (NormalizedLabel.PORT_SCAN, "vulnerability_scan", 0.95),
            "os_fingerprinting": (NormalizedLabel.PORT_SCAN, "reconnaissance", 0.95),
            "password": (NormalizedLabel.BRUTE_FORCE, "credential_access", 1.0),
            "ransomware": (NormalizedLabel.OTHER_ATTACK, "malware_ransomware", 0.95),
            "backdoor": (NormalizedLabel.OTHER_ATTACK, "malware_backdoor", 0.95),
            "sql_injection": (NormalizedLabel.OTHER_ATTACK, "web_sqli", 0.95),
            "command_injection": (NormalizedLabel.OTHER_ATTACK, "web_cmdi", 0.95),
            "xss": (NormalizedLabel.OTHER_ATTACK, "web_xss", 0.95),
            "uploading": (NormalizedLabel.OTHER_ATTACK, "web_upload", 0.95),
            "mitm": (NormalizedLabel.OTHER_ATTACK, "mitm_spoofing", 0.95),
        }
        for k, v in edge_iiotset_exact.items():
            self._exact_rules[("edge_iiotset", k)] = v

        # -------------------------------------------------------------
        # UNSW-NB15 Exact Labels (Moustafa & Slay, 2015)
        # -------------------------------------------------------------
        unsw_exact = {
            "normal": (NormalizedLabel.BENIGN, "benign", 1.0),
            "fuzzers": (NormalizedLabel.OTHER_ATTACK, "fuzzing", 0.9),
            "analysis": (NormalizedLabel.PORT_SCAN, "reconnaissance", 0.95),
            "backdoors": (NormalizedLabel.OTHER_ATTACK, "malware_backdoor", 0.95),
            "dos": (NormalizedLabel.DDOS, "denial_of_service", 0.95),
            "exploits": (NormalizedLabel.OTHER_ATTACK, "exploit", 0.9),
            "generic": (NormalizedLabel.OTHER_ATTACK, "generic_attack", 0.85),
            "reconnaissance": (NormalizedLabel.PORT_SCAN, "reconnaissance", 1.0),
            "shellcode": (NormalizedLabel.OTHER_ATTACK, "payload_shellcode", 0.95),
            "worms": (NormalizedLabel.BOTNET, "worm_propagation", 0.95),
        }
        for k, v in unsw_exact.items():
            self._exact_rules[("unsw_nb15", k)] = v

    def normalize(self, raw_label: Any, dataset_name: str = "generic") -> LabelMappingResult:
        """
        Maps raw string label to standard NormalizedLabel and category.
        """
        raw_str = str(raw_label).strip() if raw_label is not None else ""
        norm_key = raw_str.lower()
        dataset_key = dataset_name.lower()

        # 1. Exact match lookup
        if (dataset_key, norm_key) in self._exact_rules:
            n_label, cat, conf = self._exact_rules[(dataset_key, norm_key)]
            return LabelMappingResult(
                original_label=raw_str,
                normalized_label=n_label,
                attack_category=cat,
                dataset_name=dataset_name,
                confidence=conf,
                is_attack=(n_label != NormalizedLabel.BENIGN),
            )

        # 2. General cross-dataset benign detection
        if norm_key in ("0", "benign", "normal", "benigntraffic", "clean", "white"):
            return LabelMappingResult(
                original_label=raw_str,
                normalized_label=NormalizedLabel.BENIGN,
                attack_category="benign",
                dataset_name=dataset_name,
                confidence=1.0,
                is_attack=False,
            )

        # 3. Keyword / Substring heuristics
        if "portscan" in norm_key or "partofahorizontalportscan" in norm_key or "scanning" in norm_key or "pingsweep" in norm_key:
            return LabelMappingResult(
                original_label=raw_str,
                normalized_label=NormalizedLabel.PORT_SCAN,
                attack_category="reconnaissance",
                dataset_name=dataset_name,
                confidence=0.9,
                is_attack=True,
            )

        if "ddos" in norm_key:
            return LabelMappingResult(
                original_label=raw_str,
                normalized_label=NormalizedLabel.DDOS,
                attack_category="denial_of_service",
                dataset_name=dataset_name,
                confidence=0.95,
                is_attack=True,
            )

        if "bruteforce" in norm_key or "brute_force" in norm_key or "password" in norm_key or "dictionary" in norm_key:
            return LabelMappingResult(
                original_label=raw_str,
                normalized_label=NormalizedLabel.BRUTE_FORCE,
                attack_category="credential_access",
                dataset_name=dataset_name,
                confidence=0.95,
                is_attack=True,
            )

        if "heartbeat" in norm_key or "c&c-heartbeat" in norm_key or "mirai" in norm_key or "beacon" in norm_key:
            return LabelMappingResult(
                original_label=raw_str,
                normalized_label=NormalizedLabel.MIRAI_BEACON,
                attack_category="botnet_beaconing",
                dataset_name=dataset_name,
                confidence=0.85,
                is_attack=True,
            )

        if "c&c" in norm_key or "botnet" in norm_key or "okiru" in norm_key or "torii" in norm_key:
            return LabelMappingResult(
                original_label=raw_str,
                normalized_label=NormalizedLabel.BOTNET,
                attack_category="botnet_c2",
                dataset_name=dataset_name,
                confidence=0.85,
                is_attack=True,
            )

        if any(term in norm_key for term in ("dos-", "dos_", "slowloris", "synflood", "udpflood", "attack", "malicious", "injection", "xss", "backdoor", "spoof")):
            return LabelMappingResult(
                original_label=raw_str,
                normalized_label=NormalizedLabel.OTHER_ATTACK,
                attack_category="specialized_attack",
                dataset_name=dataset_name,
                confidence=0.8,
                is_attack=True,
            )

        # 4. Fallback for unrecognized strings
        return LabelMappingResult(
            original_label=raw_str,
            normalized_label=NormalizedLabel.UNKNOWN,
            attack_category="unclassified",
            dataset_name=dataset_name,
            confidence=0.3,
            is_attack=True,
        )


label_normalizer = LabelNormalizer()
