"""Rule-assisted CVE candidate reranking."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List


RULES = [
    {
        "cve": "CVE-2021-44228",
        "signals": ["log4shell_jndi", "jndi_lookup"],
        "needles": ["${jndi:"],
        "bonus": 0.75,
    },
    {
        "cve": "CVE-2021-44228",
        "signals": ["jndi_callback_protocol"],
        "any_needles": ["ldap://", "rmi://", "dns://"],
        "bonus": 0.35,
    },
    {
        "cve": "CVE-2021-44228",
        "signals": ["obfuscated_jndi_lookup"],
        "needles": ["${jnd", "ldap://"],
        "bonus": 0.7,
    },
    {
        "cve": "CVE-2021-42013",
        "signals": ["apache_path_traversal"],
        "needles": ["%2e%2e", "/cgi-bin/", "/etc/passwd"],
        "bonus": 0.45,
    },
    {
        "cve": "CVE-2021-42013",
        "signals": ["apache_cgi_path_traversal_rce"],
        "needles": ["/cgi-bin/", "%2e", "/bin/sh"],
        "bonus": 0.6,
    },
    {
        "cve": "CVE-2021-41773",
        "signals": ["apache_path_traversal"],
        "needles": ["%2e%2e", "/cgi-bin/", "/etc/passwd"],
        "bonus": 0.35,
    },
    {
        "cve": "CVE-2022-22965",
        "signals": ["spring4shell_parameters"],
        "needles": ["class.module.classloader", "pipeline.first"],
        "bonus": 0.65,
    },
    {
        "cve": "CVE-2022-22947",
        "signals": ["spring_cloud_gateway_actuator"],
        "needles": ["/actuator/gateway/routes"],
        "bonus": 0.75,
    },
    {
        "cve": "CVE-2023-43208",
        "signals": ["xstream_eventhandler_deserialization"],
        "needles": ["java.beans.eventhandler", "dynamic-proxy"],
        "bonus": 0.75,
    },
    {
        "cve": "CVE-2023-1389",
        "signals": ["tenda_luci_command_injection"],
        "needles": ["/cgi-bin/luci", "command="],
        "bonus": 0.7,
    },
    {
        "cve": "CVE-2018-20062",
        "signals": ["thinkphp_invokefunction_rce"],
        "needles": ["think", "invokefunction", "call_user_func_array"],
        "bonus": 0.7,
    },
    {
        "cve": "CVE-2019-19781",
        "signals": ["citrix_adc_vpn_path_traversal"],
        "needles": ["/vpn/", "../vpns/"],
        "bonus": 0.7,
    },
    {
        "cve": "CVE-2021-26710",
        "signals": ["xss_script_probe"],
        "needles": ["<script>", "alert(document.domain)"],
        "bonus": 0.55,
    },
]


def rerank_candidates(payload: str, candidates: List[Dict]) -> List[Dict]:
    payload_lower = payload.lower()
    by_cve: dict[str, Dict] = {}

    for item in candidates:
        cve = str(item.get("cve", "")).upper()
        if not cve:
            continue
        normalized = dict(item)
        normalized["cve"] = cve
        normalized["score"] = float(normalized.get("score", 0.0))
        normalized["retrieval_score"] = float(normalized.get("retrieval_score", normalized["score"]))
        normalized.setdefault("signals", [])
        normalized.setdefault("rule_bonus", 0.0)
        normalized.setdefault("rule_confirmed", False)
        if cve not in by_cve or normalized["retrieval_score"] > by_cve[cve]["retrieval_score"]:
            by_cve[cve] = normalized

    for rule in RULES:
        needles = rule.get("needles", [])
        any_needles = rule.get("any_needles", [])
        if all(needle in payload_lower for needle in needles) and (not any_needles or any(needle in payload_lower for needle in any_needles)):
            item = by_cve.setdefault(
                rule["cve"],
                {
                    "cve": rule["cve"],
                    "score": 0.0,
                    "retrieval_score": 0.0,
                    "source_id": None,
                    "evidence": "",
                    "neighbor_payload": "",
                    "neighbor_labels": [],
                    "signals": [],
                    "rank": None,
                    "engine": "rule",
                },
            )
            item["rule_bonus"] = round(float(item.get("rule_bonus", 0.0)) + float(rule["bonus"]), 4)
            item["rule_confirmed"] = True
            for signal in rule["signals"]:
                if signal not in item["signals"]:
                    item["signals"].append(signal)

    ranked = []
    for item in by_cve.values():
        final_score = float(item.get("retrieval_score", 0.0)) + float(item.get("rule_bonus", 0.0))
        item["final_score"] = round(final_score, 4)
        item["score"] = item["final_score"]
        ranked.append(item)

    ranked.sort(key=lambda row: (bool(row.get("rule_confirmed")), float(row.get("final_score", 0.0))), reverse=True)
    for rank, item in enumerate(ranked, start=1):
        item["final_rank"] = rank
    return ranked


def label_votes(candidates: List[Dict]) -> Dict[str, int]:
    votes: dict[str, int] = defaultdict(int)
    for item in candidates:
        for label in item.get("neighbor_labels", []) or []:
            label = str(label).upper()
            if label.startswith("CVE-"):
                votes[label] += 1
    return dict(sorted(votes.items(), key=lambda row: row[1], reverse=True))
