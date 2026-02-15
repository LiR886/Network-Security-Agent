from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, List, Optional


logger = logging.getLogger(__name__)


@dataclass
class CaptureConfig:
    mode: str = "auto"  # auto|scapy|pcap_file|mock
    interface: str = "eth0"
    bpf_filter: str = "ip"
    pcap_file: str = ""
    batch_size: int = 50
    batch_timeout_s: float = 1.0


def _safe_now() -> float:
    return time.time()


def _summarize_packet(pkt: Any) -> Dict[str, Any]:
    """
    Convert a packet into a normalized dict. Works for scapy packets and dict fallback.
    """
    if isinstance(pkt, dict):
        return pkt

    # scapy Packet
    try:
        from scapy.layers.inet import IP, TCP, UDP  # type: ignore

        d: Dict[str, Any] = {"ts": _safe_now(), "raw": None}
        if IP in pkt:
            d["src_ip"] = pkt[IP].src
            d["dst_ip"] = pkt[IP].dst
            d["proto"] = int(pkt[IP].proto)
        if TCP in pkt:
            d["l4"] = "tcp"
            d["src_port"] = int(pkt[TCP].sport)
            d["dst_port"] = int(pkt[TCP].dport)
        elif UDP in pkt:
            d["l4"] = "udp"
            d["src_port"] = int(pkt[UDP].sport)
            d["dst_port"] = int(pkt[UDP].dport)
        else:
            d["l4"] = "other"
        d["len"] = int(len(pkt))
        return d
    except Exception:
        return {"ts": _safe_now(), "parse_error": True}


async def capture_packets(cfg: CaptureConfig) -> AsyncIterator[List[Dict[str, Any]]]:
    """
    Async generator yielding batches of normalized packet dicts.

    - Uses Scapy if allowed (raw socket privileges/capabilities).
    - Falls back to mock mode if scapy sniff fails.
    """
    mode = (cfg.mode or "auto").lower()
    if mode == "scapy":
        # strict mode: if scapy capture fails, bubble up the error instead of silently mocking
        async for batch in _capture_scapy(cfg):
            yield batch
        return
    if mode == "auto":
        try:
            async for batch in _capture_scapy(cfg):
                yield batch
            return
        except Exception as e:
            logger.warning("scapy_capture_failed_falling_back_to_mock", extra={"err": str(e)})

    if mode == "pcap_file":
        async for batch in _capture_pcap_file(cfg):
            yield batch
        return

    # mock
    async for batch in _capture_mock(cfg):
        yield batch


async def _capture_scapy(cfg: CaptureConfig) -> AsyncIterator[List[Dict[str, Any]]]:
    from scapy.all import sniff  # type: ignore

    loop = asyncio.get_running_loop()

    def _sniff_once(count: int, timeout: float) -> List[Dict[str, Any]]:
        pkts = sniff(
            iface=cfg.interface,
            filter=cfg.bpf_filter or None,
            count=count,
            timeout=timeout,
            store=True,
        )
        return [_summarize_packet(p) for p in pkts]

    while True:
        batch = await loop.run_in_executor(None, _sniff_once, cfg.batch_size, cfg.batch_timeout_s)
        if batch:
            yield batch
        await asyncio.sleep(0)  # let event loop breathe


async def _capture_pcap_file(cfg: CaptureConfig) -> AsyncIterator[List[Dict[str, Any]]]:
    from scapy.all import PcapReader  # type: ignore

    if not cfg.pcap_file:
        raise ValueError("pcap_file mode requires pcap_file")

    def _iter_packets() -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        with PcapReader(cfg.pcap_file) as pr:
            for pkt in pr:
                out.append(_summarize_packet(pkt))
                if len(out) >= cfg.batch_size:
                    break
        return out

    loop = asyncio.get_running_loop()
    while True:
        batch = await loop.run_in_executor(None, _iter_packets)
        if not batch:
            return
        yield batch
        await asyncio.sleep(0)


async def _capture_mock(cfg: CaptureConfig) -> AsyncIterator[List[Dict[str, Any]]]:
    """
    Safe default for containers without CAP_NET_RAW.
    Generates synthetic "network packets" for pipeline testing.
    """
    rng_seed = int(os.getenv("NSA_MOCK_SEED", "42"))
    n = 0
    while True:
        batch: List[Dict[str, Any]] = []
        for _ in range(cfg.batch_size):
            n += 1
            # deterministic-ish pattern: every ~200 packets inject suspicious destination
            suspicious = (n + rng_seed) % 200 == 0
            batch.append(
                {
                    "ts": _safe_now(),
                    "src_ip": f"10.0.0.{(n % 200) + 1}",
                    "dst_ip": "203.0.113.66" if suspicious else f"198.51.100.{(n % 250) + 1}",
                    "proto": 6,
                    "l4": "tcp",
                    "src_port": 1024 + (n % 40000),
                    "dst_port": 22 if suspicious else (80 if (n % 2 == 0) else 443),
                    "len": 60 + (n % 1400),
                }
            )
        yield batch
        await asyncio.sleep(cfg.batch_timeout_s)


