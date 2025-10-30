# Basit gösterim (kütüphane: pip install requests python-whois bs4 tldextract)
import requests
import whois
import socket
import ssl
import ipaddress
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def _to_idna(label: str):
    try:
        return label.encode('idna').decode('ascii')
    except Exception:
        return label

def _whois_with_retries(candidate_domains):
    import time
    last_err = None
    attempts = []
    for d in candidate_domains:
        if not d:
            continue
        attempts.append(d)
        dn = _to_idna(d)
        if dn != d:
            attempts.append(dn)
    seen = set()
    attempts = [a for a in attempts if not (a in seen or seen.add(a))]
    for target in attempts:
        for _ in range(2):
            try:
                w = whois.whois(target)
                return w, target
            except Exception as e:
                last_err = e
                time.sleep(0.3)
    if last_err:
        raise last_err
    raise RuntimeError("WHOIS attempts exhausted")

def basic_url_checks(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    # WHOIS için tescilli alan adı (base domain)
    try:
        _ext = tldextract.extract(host)
        base_domain = (f"{_ext.domain}.{_ext.suffix}" if _ext.suffix else host) or host
    except Exception:
        base_domain = host
    score = 0
    reasons = []

    # IP-as-host (IPv4/IPv6)
    try:
        ipaddress.ip_address(host)
        score += 25
        reasons.append("Ana makine bir IP adresi")
    except Exception:
        pass

    # suspicious chars
    suspicious_tokens = ['@', '//', '%', '..', 'login', 'secure']
    if any(t in url.lower() for t in suspicious_tokens) and len(url) > 60:
        score += 10
        reasons.append("Şüpheli karakterler / uzun URL")

    # domain age (whois) ve ek WHOIS kontrolleri (base domain üzerinde)
    try:
        w, used_domain = _whois_with_retries([base_domain, host])
        if hasattr(w, 'creation_date') and w.creation_date:
            import datetime
            cd = w.creation_date
            # creation_date can be list/str/datetime
            if isinstance(cd, list) and cd:
                cd = cd[0]
            if isinstance(cd, str):
                parsed_cd = None
                for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y", "%Y.%m.%d %H:%M:%S"):
                    try:
                        parsed_cd = datetime.datetime.strptime(cd, fmt)
                        break
                    except Exception:
                        continue
                cd = parsed_cd or None
            if cd:
                now = datetime.datetime.now(datetime.timezone.utc)
                if hasattr(cd, 'tzinfo') and cd.tzinfo is not None:
                    try:
                        cd = cd.astimezone(datetime.timezone.utc).replace(tzinfo=None)
                    except Exception:
                        cd = cd.replace(tzinfo=None)
                age_days = (now - cd).days
                if age_days < 30:
                    score += 20
                    reasons.append(f"Alan adı yaşı {age_days} gün (WHOIS: {used_domain})")
                # çok yeni alan adını daha yüksek işaretle
                if age_days < 7:
                    score += 10
                    reasons.append(f"Alan adı çok yeni (<7 gün) (WHOIS: {used_domain})")

        # expiration kontrolü
        if hasattr(w, 'expiration_date') and w.expiration_date:
            import datetime
            ed = w.expiration_date
            if isinstance(ed, list) and ed:
                ed = ed[0]
            if isinstance(ed, str):
                parsed_ed = None
                for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y", "%Y.%m.%d %H:%M:%S"):
                    try:
                        parsed_ed = datetime.datetime.strptime(ed, fmt)
                        break
                    except Exception:
                        continue
                ed = parsed_ed or None
            if ed:
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                if hasattr(ed, 'tzinfo') and ed.tzinfo is not None:
                    try:
                        ed = ed.astimezone(datetime.timezone.utc).replace(tzinfo=None)
                    except Exception:
                        ed = ed.replace(tzinfo=None)
                days_left = (ed - now_utc).days
                if days_left >= 0 and days_left < 30:
                    score += 10
                    reasons.append(f"Alan adı yakında sona eriyor ({days_left} gün) (WHOIS: {used_domain})")

        # registrar ve nameserver basit kontrolleri
        registrar = getattr(w, 'registrar', None)
        nameservers = getattr(w, 'name_servers', None) or getattr(w, 'nameservers', None)
        if not registrar:
            reasons.append(f"WHOIS registrar bilgisi eksik veya gizli (WHOIS: {used_domain})")
        try:
            ns_count = len(list(nameservers)) if nameservers else 0
            if ns_count == 0:
                reasons.append(f"WHOIS nameserver bilgisi yok (WHOIS: {used_domain})")
            elif ns_count == 1:
                reasons.append(f"Tek nameserver kullanımı (WHOIS: {used_domain})")
        except Exception:
            pass
    except Exception:
        pass

    # HTTPS & cert check
    if parsed.scheme != 'https':
        score += 20
        reasons.append("HTTPS yok")
    else:
        try:
            def _matches_hostname(candidate_host, san_value):
                if candidate_host == san_value:
                    return True
                if san_value.startswith('*.'):
                    suffix = san_value[1:]
                    return candidate_host.endswith(suffix) and candidate_host.count('.') >= san_value.count('.')
                return False

            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(3)
                s.connect((host, 443))
                cert = s.getpeercert()
                sans = [t[1] for t in cert.get('subjectAltName', []) if t and len(t) > 1]
                if not sans:
                    score += 10
                    reasons.append("Sertifikanın SAN alanı eksik")
                else:
                    if not any(_matches_hostname(host, san) for san in sans):
                        score += 10
                        reasons.append("Sertifika SAN eşleşmiyor")
        except Exception:
            score += 20
            reasons.append("TLS bağlantısı başarısız")

    # quick content check
    try:
        r = requests.get(url, timeout=6, headers={"User-Agent": "Mozilla/5.0 (risk-checker)"})
        html = r.text.lower()
        if "password" in html or "username" in html or "sign in" in html or "oturum" in html:
            score += 10
            reasons.append("Kimlik bilgisiyle ilgili anahtar kelimeler tespit edildi")
        # form target check
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        for f in forms:
            action = f.get("action") or ""
            if action and not action.startswith('/') and urlparse(action).hostname and urlparse(action).hostname != host:
                score += 30
                reasons.append(f"Form başka bir ana makineye gönderim yapıyor: {action}")
    except Exception:
        reasons.append("İçerik alınamadı")

    return score, reasons

if __name__ == "__main__":
    import argparse, sys, json

    parser = argparse.ArgumentParser(description="Heuristic URL risk scorer")
    parser.add_argument("urls", nargs="*", help="URL listesi")
    parser.add_argument("--file", "-f", help="Satir satir URL iceren dosya")
    parser.add_argument("--json", action="store_true", help="JSON cikti formati")
    parser.add_argument("--threshold", type=int, default=30, help="Risk esigi (varsayilan: 30)")
    args = parser.parse_args()

    targets = list(args.urls)
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                targets.extend([line.strip() for line in fh if line.strip() and not line.strip().startswith("#")])
        except Exception as e:
            print(f"Dosya okunamadi: {e}", file=sys.stderr)
            sys.exit(2)

    if not targets:
        # Geriye uyumlu: ornek calistir
        targets = ["https://bit.ly/3AbCdE"]

    results = []
    worst_score = 0
    for u in targets:
        try:
            s, r = basic_url_checks(u)
        except Exception as e:
            s, r = 0, [f"Beklenmeyen hata: {e}"]
        worst_score = max(worst_score, s)
        results.append({"url": u, "score": s, "reasons": r})

    if args.json:
        print(json.dumps({"results": results}, ensure_ascii=False, indent=2))
    else:
        for item in results:
            print(f"URL: {item['url']}")
            print(f"  Skor: {item['score']}")
            print(f"  Gerekçeler: {item['reasons']}")

    # Esik asan varsa non-zero exit
    if worst_score >= args.threshold:
        sys.exit(1)
