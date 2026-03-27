"""
feeds/abuse_fetcher.py
======================
Fetches live threat intelligence from Abuse.ch feeds.

Feeds used:
  - Feodo Tracker (C2 botnet IPs):
      https://feodotracker.abuse.ch/downloads/ipblocklist.json
  - URLhaus (malware distribution URLs):
      https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/
  - ThreatFox (IPs only, via their API):
      https://threatfox-api.abuse.ch/api/v1/  (query IOC by type)

Usage:
    from feeds.abuse_fetcher import AbuseFetcher
    fetcher = AbuseFetcher()
    indicators = fetcher.fetch_all()
    feed_index = fetcher.build_index(indicators)
"""

import requests
import time
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

FEODO_URL   = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

REQUEST_TIMEOUT = 12   # seconds
MAX_RETRIES     = 2


@dataclass
class ThreatIndicator:
    indicator:  str         # IP address or domain/URL
    type:       str         # 'Malware C2', 'Botnet', 'Phishing', etc.
    source:     str         # which Abuse.ch feed
    port:       int         # associated port (0 if unknown)
    is_domain:  bool        # True if domain/URL, False if raw IP
    malware:    str         # malware family name if known
    status:     str         # 'online' / 'offline' / 'unknown'
    added:      str         # date string

    def to_dict(self) -> Dict:
        return asdict(self)


class AbuseFetcher:
    """
    Fetches and caches threat indicators from Abuse.ch feeds.
    Call fetch_all() to get a fresh list; build_index() for O(1) lookups.
    """

    def __init__(self, cache_ttl_seconds: int = 300):
        self._cache: List[ThreatIndicator] = []
        self._last_fetch: float = 0
        self._cache_ttl = cache_ttl_seconds
        self._error_log: List[str] = []

    # ── Public ───────────────────────────────────────────────────────────────

    def fetch_all(self, force: bool = False) -> List[ThreatIndicator]:
        """
        Returns combined indicators from all feeds.
        Results are cached for cache_ttl_seconds (default 5 min).
        Pass force=True to bypass cache.
        """
        now = time.time()
        if not force and self._cache and (now - self._last_fetch) < self._cache_ttl:
            logger.info(f"[AbuseFetcher] Returning cached {len(self._cache)} indicators.")
            return self._cache

        indicators: List[ThreatIndicator] = []
        self._error_log = []

        # Fetch from each feed; failures are caught individually
        indicators.extend(self._fetch_feodo())
        indicators.extend(self._fetch_urlhaus())

        # Deduplicate by indicator string
        seen = set()
        unique = []
        for ind in indicators:
            if ind.indicator not in seen:
                seen.add(ind.indicator)
                unique.append(ind)

        self._cache = unique
        self._last_fetch = now
        logger.info(f"[AbuseFetcher] Fetched {len(unique)} unique indicators.")
        return self._cache

    def build_index(
        self,
        indicators: Optional[List[ThreatIndicator]] = None
    ) -> Dict[str, ThreatIndicator]:
        """
        Builds O(1) hash map: indicator_string → ThreatIndicator.
        If indicators is None, uses the last cached fetch.
        """
        source = indicators if indicators is not None else self._cache
        return {ind.indicator: ind for ind in source}

    def get_status(self) -> Dict:
        """Summary of current feed state for the /api/feed-status endpoint."""
        return {
            'total_indicators': len(self._cache),
            'last_fetch':       self._last_fetch,
            'cache_age_seconds': round(time.time() - self._last_fetch, 1)
                                  if self._last_fetch else None,
            'errors':           self._error_log,
        }

    # ── Private: per-feed fetchers ────────────────────────────────────────────

    def _get(self, url: str, method: str = 'GET', json_body: dict = None) -> Optional[dict]:
        """Shared HTTP helper with retry logic."""
        for attempt in range(MAX_RETRIES + 1):
            try:
                if method == 'POST':
                    resp = requests.post(url, json=json_body, timeout=REQUEST_TIMEOUT)
                else:
                    resp = requests.get(url, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.Timeout:
                err = f"Timeout fetching {url} (attempt {attempt+1})"
                logger.warning(err)
                if attempt == MAX_RETRIES:
                    self._error_log.append(err)
            except requests.exceptions.ConnectionError:
                err = f"Connection error fetching {url}"
                logger.warning(err)
                self._error_log.append(err)
                return None
            except Exception as e:
                err = f"Error fetching {url}: {e}"
                logger.warning(err)
                self._error_log.append(err)
                return None
        return None

    def _fetch_feodo(self) -> List[ThreatIndicator]:
        """
        Feodo Tracker — botnet C2 IP blocklist.
        Returns IP addresses of active botnet command-and-control servers.
        JSON format: [ {ip_address, port, status, malware, first_seen, ...}, ... ]
        """
        data = self._get(FEODO_URL)
        if not data:
            logger.warning("[AbuseFetcher] Feodo Tracker fetch failed — using empty list.")
            return []

        indicators = []
        for entry in data[:200]:   # cap at 200 to avoid memory issues
            ip  = entry.get('ip_address', '').strip()
            if not ip:
                continue

            malware = entry.get('malware', 'Unknown')
            status  = entry.get('status', 'unknown').lower()
            port    = int(entry.get('port', 0) or 0)
            date    = entry.get('first_seen', '')

            # Map Feodo malware names to our threat types
            threat_type = _map_feodo_malware(malware)

            indicators.append(ThreatIndicator(
                indicator = ip,
                type      = threat_type,
                source    = 'Abuse.ch Feodo',
                port      = port,
                is_domain = False,
                malware   = malware,
                status    = status,
                added     = date,
            ))

        logger.info(f"[AbuseFetcher] Feodo: {len(indicators)} IPs loaded.")
        return indicators

    def _fetch_urlhaus(self) -> List[ThreatIndicator]:
        """
        URLhaus — malware distribution URLs (recent 100).
        JSON format: { urls: [ {url, url_status, host, tags, ...}, ... ] }
        """
        data = self._get(URLHAUS_URL)
        if not data:
            logger.warning("[AbuseFetcher] URLhaus fetch failed — using empty list.")
            return []

        urls = data.get('urls', [])
        indicators = []

        for entry in urls[:100]:
            url    = entry.get('url', '').strip()
            host   = entry.get('host', '').strip()
            status = entry.get('url_status', 'unknown').lower()
            tags   = entry.get('tags', []) or []
            date   = entry.get('date_added', '')

            # Use the host (IP or domain) as the indicator
            indicator_str = host if host else url
            if not indicator_str:
                continue

            is_domain = not _is_ip(indicator_str)
            malware   = ', '.join(tags) if tags else 'Unknown'
            threat_type = 'Malware C2' if 'malware' in malware.lower() else 'Phishing'

            indicators.append(ThreatIndicator(
                indicator = indicator_str,
                type      = threat_type,
                source    = 'Abuse.ch URLhaus',
                port      = 80,
                is_domain = is_domain,
                malware   = malware,
                status    = status,
                added     = date,
            ))

        logger.info(f"[AbuseFetcher] URLhaus: {len(indicators)} indicators loaded.")
        return indicators


# ── Helpers ───────────────────────────────────────────────────────────────────

def _map_feodo_malware(malware_name: str) -> str:
    """Map Feodo Tracker malware family names to our threat type labels."""
    name = malware_name.lower()
    mapping = {
        'emotet':        'Malware C2',
        'dridex':        'Malware C2',
        'trickbot':      'Malware C2',
        'qakbot':        'Malware C2',
        'qbot':          'Malware C2',
        'cobalt strike': 'Malware C2',
        'buer':          'Malware C2',
        'bazarloader':   'Malware C2',
        'asyncrat':      'Malware C2',
        'mirai':         'Botnet',
        'mozi':          'Botnet',
        'hajime':        'Botnet',
        'lokibot':       'Phishing',
        'formbook':      'Phishing',
        'azorult':       'Phishing',
        'wannacry':      'Ransomware',
        'lockbit':       'Ransomware',
        'conti':         'Ransomware',
        'revil':         'Ransomware',
        'blackcat':      'Ransomware',
        'alphv':         'Ransomware',
    }
    for key, val in mapping.items():
        if key in name:
            return val
    return 'Malware C2'


def _is_ip(value: str) -> bool:
    """Return True if value looks like an IPv4 address."""
    parts = value.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
