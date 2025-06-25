from flask import Flask, request, Response
import requests
from urllib.parse import urlparse, urljoin, quote, unquote
import re
import traceback
import time
from threading import Lock
import gc
from collections import OrderedDict
import base64
from urllib.parse import quote_plus

app = Flask(__name__)

# --- CONFIGURAZIONE CACHE OTTIMIZZATA ---
CACHE_TTL = 30  # Ridotto da 60 a 30 secondi
MAX_CACHE_SIZE = 50  # Limite massimo di elementi in cache
MAX_TS_SIZE = 5 * 1024 * 1024  # Massimo 5MB per segmento TS
MAX_TOTAL_CACHE_SIZE = 100 * 1024 * 1024  # Massimo 100MB totali in cache

# Cache LRU (Least Recently Used) ottimizzate
class LRUCache:
    def __init__(self, max_size, max_item_size=None):
        self.max_size = max_size
        self.max_item_size = max_item_size
        self.cache = OrderedDict()
        self.lock = Lock()
        self.current_size = 0  # Traccia la dimensione totale in byte

    def get(self, key):
        with self.lock:
            if key in self.cache:
                timestamp, value = self.cache[key]
                if time.time() - timestamp < CACHE_TTL:
                    # Sposta alla fine (most recently used)
                    self.cache.move_to_end(key)
                    return value
                else:
                    # Rimuovi elemento scaduto
                    self._remove_item(key)
            return None

    def put(self, key, value):
        with self.lock:
            # Controlla dimensione dell'elemento
            value_size = len(value) if isinstance(value, (bytes, str)) else 0
            if self.max_item_size and value_size > self.max_item_size:
                return  # Non cachare elementi troppo grandi

            # Rimuovi elemento esistente se presente
            if key in self.cache:
                self._remove_item(key)

            # Assicurati che ci sia spazio
            while len(self.cache) >= self.max_size or self.current_size + value_size > MAX_TOTAL_CACHE_SIZE:
                if not self.cache:
                    break
                self._remove_oldest()

            # Aggiungi nuovo elemento
            self.cache[key] = (time.time(), value)
            self.current_size += value_size

    def _remove_item(self, key):
        if key in self.cache:
            _, value = self.cache[key]
            value_size = len(value) if isinstance(value, (bytes, str)) else 0
            self.current_size -= value_size
            del self.cache[key]

    def _remove_oldest(self):
        if self.cache:
            oldest_key = next(iter(self.cache))
            self._remove_item(oldest_key)

    def cleanup_expired(self):
        """Rimuove elementi scaduti"""
        with self.lock:
            current_time = time.time()
            expired_keys = [
                key for key, (timestamp, _) in self.cache.items()
                if current_time - timestamp >= CACHE_TTL
            ]
            for key in expired_keys:
                self._remove_item(key)

    def clear(self):
        """Svuota completamente la cache"""
        with self.lock:
            self.cache.clear()
            self.current_size = 0

# Inizializza cache ottimizzate
ts_cache = LRUCache(MAX_CACHE_SIZE, MAX_TS_SIZE)
key_cache = LRUCache(MAX_CACHE_SIZE // 2)  # Cache più piccola per le chiavi

# Timer per pulizia periodica
last_cleanup = time.time()
CLEANUP_INTERVAL = 60  # Pulizia ogni 60 secondi

def periodic_cleanup():
    """Pulizia periodica delle cache"""
    global last_cleanup
    current_time = time.time()
    if current_time - last_cleanup > CLEANUP_INTERVAL:
        ts_cache.cleanup_expired()
        key_cache.cleanup_expired()
        gc.collect()  # Forza garbage collection
        last_cleanup = current_time

def detect_m3u_type(content):
    """Rileva se è un M3U (lista IPTV) o un M3U8 (flusso HLS)"""
    if "#EXTM3U" in content and "#EXTINF" in content:
        return "m3u8"
    return "m3u"

def replace_key_uri(line, headers_query):
    """Sostituisce l'URI della chiave AES-128 con il proxy"""
    match = re.search(r'URI="([^"]+)"', line)
    if match:
        key_url = match.group(1)
        proxied_key_url = f"/proxy/key?url={quote(key_url)}&{headers_query}"
        return line.replace(key_url, proxied_key_url)
    return line

def extract_channel_id(url):
    """Estrae l'ID del canale da vari formati URL"""

    # Pattern per premium/mono.m3u8
    match_premium = re.search(r'/premium(\d+)/mono\.m3u8$', url)
    if match_premium:
        return match_premium.group(1)

    # Pattern per watch/stream-ID.php
    match_watch = re.search(r'/watch/stream-(\d+)\.php$', url)
    if match_watch:
        return match_watch.group(1)

    # Pattern per stream/stream-ID.php
    match_stream = re.search(r'/stream/stream-(\d+)\.php$', url)
    if match_stream:
        return match_stream.group(1)

    # Estrai da URL generici contenenti numeri
    match_generic = re.search(r'(\d+)', url)
    if match_generic:
        return match_generic.group(1)

    return None

def process_daddylive_url(url):
    """Converte URL vecchi in formati compatibili con DaddyLive 2025"""

    # Converti premium URLs in formato watch
    match_premium = re.search(r'/premium(\d+)/mono\.m3u8$', url)
    if match_premium:
        channel_id = match_premium.group(1)
        new_url = f"https://daddylive.mp/watch/stream-{channel_id}.php"
        print(f"URL processato da {url} a {new_url}")
        return new_url

    # Se è già un URL DaddyLive moderno, usalo direttamente
    if 'daddylive.mp' in url and ('watch/' in url or 'stream/' in url):
        return url

    # Se contiene solo numeri, crea URL watch
    if url.isdigit():
        return f"https://daddylive.mp/watch/stream-{url}.php"

    return url

def resolve_m3u8_link(url, headers=None):
    """
    Risolve URL DaddyLive usando il metodo esatto di addon.py PlayStream
    """
    if not url:
        print("Errore: URL non fornito.")
        return {"resolved_url": None, "headers": {}}

    print(f"Tentativo di risoluzione URL: {url}")

    # Header di default identici a addon.py
    current_headers = headers if headers else {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
        'Referer': 'https://daddylive.mp/',
        'Origin': 'https://daddylive.mp'
    }

    try:
        # Ottieni URL base dinamico
        print("Ottengo URL base dinamico...")
        main_url = requests.get(
            'https://raw.githubusercontent.com/thecrewwh/dl_url/refs/heads/main/dl.xml',
            timeout=5
        ).text
        baseurl = re.findall(r'src = "([^"]*)', main_url)[0]  # ✅ CORRETTO con raw string
        print(f"URL base ottenuto: {baseurl}")

        # Estrai ID del canale dall'URL
        channel_id = extract_channel_id(url)
        if not channel_id:
            print("Impossibile estrarre ID canale")
            return {"resolved_url": url, "headers": current_headers}

        print(f"ID canale estratto: {channel_id}")

        # Costruisci URL del stream (identico a addon.py)
        stream_url = f"{baseurl}stream/stream-{channel_id}.php"
        print(f"URL stream costruito: {stream_url}")

        # Aggiorna header con baseurl corretto
        current_headers['Referer'] = baseurl + '/'
        current_headers['Origin'] = baseurl

        # PASSO 1: Richiesta alla pagina stream per cercare Player 2
        print(f"Passo 1: Richiesta a {stream_url}")
        response = requests.get(stream_url, headers=current_headers, timeout=10)
        response.raise_for_status()

        # Cerca link Player 2 (metodo esatto da addon.py)
        iframes = re.findall(r'<a[^>]*href="([^"]+)"[^>]*>\s*<button[^>]*>\s*Player\s*2\s*<\/button>', response.text)
        if not iframes:
            print("Nessun link Player 2 trovato")
            return {"resolved_url": url, "headers": current_headers}

        print(f"Passo 2: Trovato link Player 2: {iframes[0]}")

        # PASSO 2: Segui il link Player 2
        url2 = iframes[0]
        url2 = baseurl + url2
        url2 = url2.replace('//cast', '/cast')  # Fix da addon.py

        # Aggiorna header
        current_headers['Referer'] = url2
        current_headers['Origin'] = url2

        print(f"Passo 3: Richiesta a Player 2: {url2}")
        response = requests.get(url2, headers=current_headers, timeout=10)
        response.raise_for_status()

        # PASSO 3: Cerca iframe nella risposta Player 2
        iframes = re.findall(r'iframe src="([^"]*)', response.text)  # ✅ CORRETTO con raw string
        if not iframes:
            print("Nessun iframe trovato nella pagina Player 2")
            return {"resolved_url": url, "headers": current_headers}

        iframe_url = iframes[0]
        print(f"Passo 4: Trovato iframe: {iframe_url}")

        # PASSO 4: Accedi all'iframe
        print(f"Passo 5: Richiesta iframe: {iframe_url}")
        response = requests.get(iframe_url, headers=current_headers, timeout=10)
        response.raise_for_status()

        iframe_content = response.text

        # PASSO 5: Estrai parametri dall'iframe (metodo esatto addon.py)
        try:
            channel_key = re.findall(r'(?s) channelKey = \"([^"]*)', iframe_content)[0]  # ✅ CORRETTO

            # Estrai e decodifica parametri base64
            auth_ts_b64 = re.findall(r'(?s)c = atob\("([^"]*)', iframe_content)[0]  # ✅ CORRETTO
            auth_ts = base64.b64decode(auth_ts_b64).decode('utf-8')

            auth_rnd_b64 = re.findall(r'(?s)d = atob\("([^"]*)', iframe_content)[0]  # ✅ CORRETTO
            auth_rnd = base64.b64decode(auth_rnd_b64).decode('utf-8')

            auth_sig_b64 = re.findall(r'(?s)e = atob\("([^"]*)', iframe_content)[0]  # ✅ CORRETTO
            auth_sig = base64.b64decode(auth_sig_b64).decode('utf-8')
            auth_sig = quote_plus(auth_sig)

            auth_host_b64 = re.findall(r'(?s)a = atob\("([^"]*)', iframe_content)[0]  # ✅ CORRETTO
            auth_host = base64.b64decode(auth_host_b64).decode('utf-8')

            auth_php_b64 = re.findall(r'(?s)b = atob\("([^"]*)', iframe_content)[0]  # ✅ CORRETTO
            auth_php = base64.b64decode(auth_php_b64).decode('utf-8')

            print(f"Parametri estratti: channel_key={channel_key}")

        except (IndexError, Exception) as e:
            print(f"Errore estrazione parametri: {e}")
            return {"resolved_url": url, "headers": current_headers}

        # PASSO 6: Richiesta di autenticazione
        auth_url = f'{auth_host}{auth_php}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
        print(f"Passo 6: Autenticazione: {auth_url}")

        auth_response = requests.get(auth_url, headers=current_headers, timeout=10)
        auth_response.raise_for_status()

        # PASSO 7: Estrai host e server lookup
        host = re.findall(r'(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)', iframe_content)[0]  # ✅ CORRETTO
        server_lookup = re.findall(r'n fetchWithRetry\(\s*\'([^\']*)', iframe_content)[0]  # ✅ CORRETTO

        # PASSO 8: Server lookup per ottenere server_key
        server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup}{channel_key}"
        print(f"Passo 7: Server lookup: {server_lookup_url}")

        lookup_response = requests.get(server_lookup_url, headers=current_headers, timeout=10)
        lookup_response.raise_for_status()
        server_data = lookup_response.json()
        server_key = server_data['server_key']

        print(f"Server key ottenuto: {server_key}")

        # PASSO 9: Costruisci URL M3U8 finale SENZA parametri proxy
        referer_raw = f'https://{urlparse(iframe_url).netloc}'

        # URL base M3U8 PULITO (senza parametri proxy)
        clean_m3u8_url = f'https://{server_key}{host}{server_key}/{channel_key}/mono.m3u8'

        print(f"URL M3U8 pulito costruito: {clean_m3u8_url}")

        # Header corretti per il fetch
        final_headers = {
            'User-Agent': current_headers.get('User-Agent', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'),
            'Referer': referer_raw,
            'Origin': referer_raw
        }

        return {
            "resolved_url": clean_m3u8_url,  # URL PULITO senza parametri proxy
            "headers": final_headers          # Header corretti
        }

    except Exception as e:
        print(f"Errore durante la risoluzione: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return {"resolved_url": url, "headers": current_headers}

@app.route('/proxy/m3u')
def proxy_m3u():
    """Proxy per file M3U e M3U8 con supporto DaddyLive 2025"""
    periodic_cleanup()  # Pulizia periodica

    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    # Header di default aggiornati per DaddyLive 2025
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Referer": "https://daddylive.mp/",
        "Origin": "https://daddylive.mp"
    }

    # Estrai gli header dalla richiesta, sovrascrivendo i default
    request_headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    headers = {**default_headers, **request_headers}

    # Processa URL con nuova logica DaddyLive 2025
    processed_url = process_daddylive_url(m3u_url)

    try:
        print(f"Chiamata a resolve_m3u8_link per URL processato: {processed_url}")
        result = resolve_m3u8_link(processed_url, headers)
        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL in un M3U8 valido.", 500

        resolved_url = result["resolved_url"]
        current_headers_for_proxy = result["headers"]

        print(f"Risoluzione completata. URL M3U8 finale: {resolved_url}")

        # CORREZIONE: Verifica che sia un M3U8 valido (senza parametri proxy)
        if not resolved_url.endswith('.m3u8'):
            print(f"URL risolto non è un M3U8: {resolved_url}")
            return "Errore: Impossibile ottenere un M3U8 valido dal canale", 500

        # Fetchare il contenuto M3U8 effettivo dall'URL pulito
        print(f"Fetching M3U8 content from clean URL: {resolved_url}")
        print(f"Using headers: {current_headers_for_proxy}")

        m3u_response = requests.get(resolved_url, headers=current_headers_for_proxy, allow_redirects=True, timeout=5)
        m3u_response.raise_for_status()

        m3u_content = m3u_response.text
        final_url = m3u_response.url

        # Processa il contenuto M3U8
        file_type = detect_m3u_type(m3u_content)
        if file_type == "m3u":
            return Response(m3u_content, content_type="application/vnd.apple.mpegurl")

        # Processa contenuto M3U8
        parsed_url = urlparse(final_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path.rsplit('/', 1)[0]}/"

        # Prepara la query degli header per segmenti/chiavi proxati
        headers_query = "&".join([f"h_{quote(k)}={quote(v)}" for k, v in current_headers_for_proxy.items()])

        modified_m3u8 = []
        for line in m3u_content.splitlines():
            line = line.strip()
            if line.startswith("#EXT-X-KEY") and 'URI="' in line:
                line = replace_key_uri(line, headers_query)
            elif line and not line.startswith("#"):
                segment_url = urljoin(base_url, line)
                line = f"/proxy/ts?url={quote(segment_url)}&{headers_query}"
            modified_m3u8.append(line)

        modified_m3u8_content = "\n".join(modified_m3u8)
        return Response(modified_m3u8_content, content_type="application/vnd.apple.mpegurl")

    except requests.RequestException as e:
        print(f"Errore durante il download o la risoluzione del file: {str(e)}")
        return f"Errore durante il download o la risoluzione del file M3U/M3U8: {str(e)}", 500
    except Exception as e:
        print(f"Errore generico nella funzione proxy_m3u: {str(e)}")
        return f"Errore generico durante l'elaborazione: {str(e)}", 500


@app.route('/proxy/resolve')
def proxy_resolve():
    """Proxy per risolvere e restituire un URL M3U8 con metodo DaddyLive 2025"""
    periodic_cleanup()

    url = request.args.get('url', '').strip()
    if not url:
        return "Errore: Parametro 'url' mancante", 400

    # AGGIUNTA: Header di default identici a /proxy/m3u
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "Referer": "https://daddylive.mp/",
        "Origin": "https://daddylive.mp"
    }

    # Estrai gli header dalla richiesta, sovrascrivendo i default
    request_headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    headers = {**default_headers, **request_headers}

    try:
        processed_url = process_daddylive_url(url)
        result = resolve_m3u8_link(processed_url, headers)
        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL", 500

        headers_query = "&".join([f"h_{quote(k)}={quote(v)}" for k, v in result["headers"].items()])
        return Response(
            f"#EXTM3U\n"
            f"#EXTINF:-1,Canale Risolto\n"
            f"/proxy/m3u?url={quote(result['resolved_url'])}&{headers_query}",
            content_type="application/vnd.apple.mpegurl"
        )

    except Exception as e:
        return f"Errore durante la risoluzione dell'URL: {str(e)}", 500


@app.route('/proxy/ts')
def proxy_ts():
    """Proxy per segmenti .TS con headers personalizzati e caching ottimizzato"""
    periodic_cleanup()

    ts_url = request.args.get('url', '').strip()
    if not ts_url:
        return "Errore: Parametro 'url' mancante", 400

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    # Controlla cache
    cached_data = ts_cache.get(ts_url)
    if cached_data:
        return Response(cached_data, content_type="video/mp2t")

    try:
        response = requests.get(ts_url, headers=headers, stream=True, allow_redirects=True, timeout=10)
        response.raise_for_status()

        # Leggi in chunks per evitare di caricare tutto in memoria
        data = b''
        for chunk in response.iter_content(chunk_size=8192):
            data += chunk
            # Limite di sicurezza per evitare segmenti troppo grandi
            if len(data) > MAX_TS_SIZE:
                break

        # Carica in cache solo se non troppo grande
        if len(data) <= MAX_TS_SIZE:
            ts_cache.put(ts_url, data)

        return Response(data, content_type="video/mp2t")

    except requests.RequestException as e:
        return f"Errore durante il download del segmento TS: {str(e)}", 500

@app.route('/proxy/key')
def proxy_key():
    """Proxy per la chiave AES-128 con header personalizzati"""
    key_url = request.args.get('url', '').strip()
    if not key_url:
        return "Errore: Parametro 'url' mancante per la chiave", 400

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    # Controlla cache per le chiavi
    cached_key = key_cache.get(key_url)
    if cached_key:
        return Response(cached_key, content_type="application/octet-stream")

    try:
        response = requests.get(key_url, headers=headers, allow_redirects=True, timeout=10)
        response.raise_for_status()

        # Le chiavi sono piccole, cachale sempre
        key_cache.put(key_url, response.content)

        return Response(response.content, content_type="application/octet-stream")

    except requests.RequestException as e:
        return f"Errore durante il download della chiave AES-128: {str(e)}", 500

@app.route('/cache/stats')
def cache_stats():
    """Endpoint per monitorare lo stato della cache"""
    return {
        "ts_cache_size": len(ts_cache.cache),
        "ts_cache_bytes": ts_cache.current_size,
        "key_cache_size": len(key_cache.cache),
        "key_cache_bytes": key_cache.current_size,
        "total_bytes": ts_cache.current_size + key_cache.current_size,
        "max_total_bytes": MAX_TOTAL_CACHE_SIZE,
        "cache_ttl": CACHE_TTL,
        "max_ts_size": MAX_TS_SIZE
    }

@app.route('/cache/clear')
def clear_cache():
    """Endpoint per svuotare manualmente la cache"""
    ts_cache.clear()
    key_cache.clear()
    gc.collect()
    return "Cache svuotata con successo"

@app.route('/')
def index():
    """Pagina principale che mostra un messaggio di benvenuto"""
    return "Proxy DaddyLive 2025 - Metodo Addon.py Funzionante!"

if __name__ == '__main__':
    print("Proxy DaddyLive 2025 - Metodo Addon.py Funzionante!")
    app.run(host="0.0.0.0", port=7860, debug=False)
