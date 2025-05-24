from flask import Flask, request, Response
import requests
from urllib.parse import urlparse, urljoin, quote, unquote
import re
import traceback
import time
from threading import Lock
import gc
from collections import OrderedDict

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

def resolve_m3u8_link(url, headers=None):
    """
    Tenta di risolvere un URL M3U8.
    Prova prima la logica specifica per iframe (tipo Daddylive), inclusa la lookup della server_key.
    Se fallisce, verifica se l'URL iniziale era un M3U8 diretto e lo restituisce.
    """
    if not url:
        print("Errore: URL non fornito.")
        return {"resolved_url": None, "headers": {}}

    print(f"Tentativo di risoluzione URL: {url}")
    # Utilizza gli header forniti, altrimenti usa un User-Agent di default
    current_headers = headers if headers else {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0+Safari/537.36'}

    initial_response_text = None
    final_url_after_redirects = None

    try:
        # Utilizza una sessione per gestire i cookie e i redirect
        with requests.Session() as session:
            # Imposta timeout più aggressivi per ridurre l'uso di memoria
            session.timeout = 5
            
            # Primo passo: Richiesta all'URL iniziale
            print(f"Passo 1: Richiesta a {url}")
            response = session.get(url, headers=current_headers, allow_redirects=True, timeout=5)
            response.raise_for_status()
            initial_response_text = response.text
            final_url_after_redirects = response.url
            print(f"Passo 1 completato. URL finale dopo redirect: {final_url_after_redirects}")

            # Prova la logica dell'iframe
            print("Tentativo con logica iframe...")
            try:
                # Secondo passo (Iframe): Trova l'iframe src nella risposta iniziale
                iframes = re.findall(r'iframe src="([^"]+)', initial_response_text)
                if not iframes:
                    raise ValueError("Nessun iframe src trovato.")

                url2 = iframes[0]
                print(f"Passo 2 (Iframe): Trovato iframe URL: {url2}")

                # Terzo passo (Iframe): Richiesta all'URL dell'iframe
                referer_raw = urlparse(url2).scheme + "://" + urlparse(url2).netloc + "/"
                origin_raw = urlparse(url2).scheme + "://" + urlparse(url2).netloc
                current_headers['Referer'] = referer_raw
                current_headers['Origin'] = origin_raw
                print(f"Passo 3 (Iframe): Richiesta a {url2}")
                response = session.get(url2, headers=current_headers, timeout=5)
                response.raise_for_status()
                iframe_response_text = response.text
                print("Passo 3 (Iframe) completato.")

                # Quarto passo (Iframe): Estrai parametri dinamici dall'iframe response
                channel_key_match = re.search(r'(?s) channelKey = \"([^"]*)', iframe_response_text)
                auth_ts_match = re.search(r'(?s) authTs\s*= \"([^"]*)', iframe_response_text)
                auth_rnd_match = re.search(r'(?s) authRnd\s*= \"([^"]*)', iframe_response_text)
                auth_sig_match = re.search(r'(?s) authSig\s*= \"([^"]*)', iframe_response_text)
                auth_host_match = re.search(r'\}\s*fetchWithRetry\(\s*\'([^\']*)', iframe_response_text)
                server_lookup_match = re.search('n fetchWithRetry\(\s*\'([^\']*)', iframe_response_text)

                if not all([channel_key_match, auth_ts_match, auth_rnd_match, auth_sig_match, auth_host_match, server_lookup_match]):
                     raise ValueError("Impossibile estrarre tutti i parametri dinamici dall'iframe response.")

                channel_key = channel_key_match.group(1)
                auth_ts = auth_ts_match.group(1)
                auth_rnd = auth_rnd_match.group(1)
                auth_sig = quote(auth_sig_match.group(1))
                auth_host = auth_host_match.group(1)
                server_lookup = server_lookup_match.group(1)

                print("Passo 4 (Iframe): Parametri dinamici estratti.")

                # Quinto passo (Iframe): Richiesta di autenticazione
                auth_url = f'{auth_host}{channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
                print(f"Passo 5 (Iframe): Richiesta di autenticazione a {auth_url}")
                auth_response = session.get(auth_url, headers=current_headers, timeout=5)
                auth_response.raise_for_status()
                print("Passo 5 (Iframe) completato.")

                # Sesto passo (Iframe): Richiesta di server lookup per ottenere la server_key
                server_lookup_url = f"https://{urlparse(url2).netloc}{server_lookup}{channel_key}"
                print(f"Passo 6 (Iframe): Richiesta server lookup a {server_lookup_url}")
                server_lookup_response = session.get(server_lookup_url, headers=current_headers, timeout=5)
                server_lookup_response.raise_for_status()
                server_lookup_data = server_lookup_response.json()
                print("Passo 6 (Iframe) completato.")

                # Settimo passo (Iframe): Estrai server_key dalla risposta di server lookup
                server_key = server_lookup_data.get('server_key')
                if not server_key:
                    raise ValueError("'server_key' non trovato nella risposta di server lookup.")
                print(f"Passo 7 (Iframe): Estratto server_key: {server_key}")

                # Ottavo passo (Iframe): Costruisci il link finale
                host_match = re.search('(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)', iframe_response_text)
                if not host_match:
                     raise ValueError("Impossibile trovare l'host finale per l'm3u8.")
                host = host_match.group(1)
                print(f"Passo 8 (Iframe): Trovato host finale per m3u8: {host}")

                # Costruisci l'URL finale del flusso
                final_stream_url = (
                    f'https://{server_key}{host}{server_key}/{channel_key}/mono.m3u8'
                )

                # Prepara gli header per lo streaming
                stream_headers = {
                    'User-Agent': current_headers.get('User-Agent', ''),
                    'Referer': referer_raw,
                    'Origin': origin_raw
                }
                
                return {
                    "resolved_url": final_stream_url,
                    "headers": stream_headers
                }

            except (ValueError, requests.exceptions.RequestException) as e:
                print(f"Logica iframe fallita: {e}")
                print("Tentativo fallback: verifica se l'URL iniziale era un M3U8 diretto...")

                # Fallback: Verifica se la risposta iniziale era un file M3U8 diretto
                if initial_response_text and initial_response_text.strip().startswith('#EXTM3U'):
                    print("Fallback riuscito: Trovato file M3U8 diretto.")
                    return {
                        "resolved_url": final_url_after_redirects,
                        "headers": current_headers
                    }
                else:
                    print("Fallback fallito: La risposta iniziale non era un M3U8 diretto.")
                    return {
                        "resolved_url": url,
                        "headers": current_headers
                    }

    except requests.exceptions.RequestException as e:
        print(f"Errore durante la richiesta HTTP iniziale: {e}")
        return {"resolved_url": url, "headers": current_headers}
    except Exception as e:
        print(f"Errore generico durante la risoluzione: {e}")
        return {"resolved_url": url, "headers": current_headers}

@app.route('/proxy/m3u')
def proxy_m3u():
    """Proxy per file M3U e M3U8 con supporto per redirezioni e header personalizzati"""
    periodic_cleanup()  # Pulizia periodica
    
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    default_headers = {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/33.0 Mobile/15E148 Safari/605.1.15",
        "Referer": "https://vavoo.to/",
        "Origin": "https://vavoo.to"
    }

    # Estrai gli header dalla richiesta, sovrascrivendo i default
    request_headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }
    headers = {**default_headers, **request_headers}

    # --- Logica per trasformare l'URL se necessario ---
    processed_url = m3u_url
    match_premium_m3u8 = re.search(r'/premium(\d+)/mono\.m3u8$', m3u_url)

    if match_premium_m3u8:
        channel_number = match_premium_m3u8.group(1)
        transformed_url = f"https://daddylive.dad/embed/stream-{channel_number}.php"
        print(f"URL {m3u_url} corrisponde al pattern premium. Trasformato in: {transformed_url}")
        processed_url = transformed_url
    else:
        print(f"URL {m3u_url} non corrisponde al pattern premium/mono.m3u8. Utilizzo URL originale.")

    try:
        print(f"Chiamata a resolve_m3u8_link per URL processato: {processed_url}")
        result = resolve_m3u8_link(processed_url, headers)

        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL in un M3U8 valido.", 500

        resolved_url = result["resolved_url"]
        current_headers_for_proxy = result["headers"]

        print(f"Risoluzione completata. URL M3U8 finale: {resolved_url}")

        # Fetchare il contenuto M3U8 effettivo dall'URL risolto
        print(f"Fetching M3U8 content from resolved URL: {resolved_url}")
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
    """Proxy per risolvere e restituire un URL M3U8"""
    periodic_cleanup()
    
    url = request.args.get('url', '').strip()
    if not url:
        return "Errore: Parametro 'url' mancante", 400

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    try:
        result = resolve_m3u8_link(url, headers)
        
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
        response = requests.get(ts_url, headers=headers, stream=True, allow_redirects=True, timeout=5)
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
        response = requests.get(key_url, headers=headers, allow_redirects=True, timeout=5)
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
    return "Proxy started!"

if __name__ == '__main__':
    print("Proxy started!")
    app.run(host="0.0.0.0", port=7860, debug=False)
