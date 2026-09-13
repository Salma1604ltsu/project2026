from urllib.parse import urljoin, urldefrag
from bs4 import BeautifulSoup


def discover_links(base_url, html, limit=30):
    soup = BeautifulSoup(html, "html.parser")
    links = []
    seen = set()
    for anchor in soup.find_all("a", href=True):
        target, _ = urldefrag(urljoin(base_url, anchor["href"]))
        if target.startswith(base_url) and target not in seen:
            seen.add(target)
            links.append(target)
        if len(links) >= limit:
            break
    return links
