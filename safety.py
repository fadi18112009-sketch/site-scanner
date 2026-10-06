import ipaddress, socket
from urllib.parse import urlparse, urljoin
import requests

def is_safe_host(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True

def safe_get(url, hops=5, **kw):
    for _ in range(hops):
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname or not is_safe_host(p.hostname):
            raise ValueError("blocked")
        r = requests.get(url, allow_redirects=False, **kw)
        if r.is_redirect:
            url = urljoin(url, r.headers.get("Location", ""))
            continue
        return r
    raise ValueError("too many redirects")
