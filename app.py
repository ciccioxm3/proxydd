from flask import Flask, request, Response
import requests
from urllib.parse import urlparse, urljoin, quote, unquote
import re
import json
import base64
import os
import random
from dotenv import load_dotenv
from cachetools import TTLCache, LRUCache

load_dotenv()  # Carica le variabili dal file .env

app = Flask(__name__)

# --- Configurazione Cache ---
# Cache per le playlist M3U8. TTL di 5 secondi per garantire l'aggiornamento dei live stream.
M3U8_CACHE = TTLCache(maxsize=200, ttl=5)
# Cache per i segmenti TS. LRU (Least Recently Used) per mantenere i segmenti più richiesti.
TS_CACHE = LRUCache(maxsize=1000)  # Mantiene in memoria i 1000 segmenti usati più di recente
# Cache per le chiavi di decriptazione.
# RIMOSSO: KEY_CACHE non più utilizzata per proxying chiavi AES
# --- Configurazione Proxy ---
# I proxy possono essere in formato http, https, socks5, socks5h. Es: 'socks5://user:pass@host:port'
# È possibile specificare una lista di proxy separati da virgola. Verrà scelto uno a caso.
NEWKSO_PROXY = os.getenv('NEWKSO_PROXY', None)
NEWKSO_SSL_VERIFY = os.getenv('NEWKSO_SSL_VERIFY', 'false').lower() == 'true'

# Fetch Daddylive base URL at startup
DADDY_LIVE_BASE_URL = None
try:
    main_url_response = requests.get('https://raw.githubusercontent.com/thecrewwh/dl_url/refs/heads/main/dl.xml', timeout=5)
    main_url_response.raise_for_status()
    DADDY_LIVE_BASE_URL = re.findall('src = "([^"]*)', main_url_response.text)[0]
    app.logger.info(f"DADDY_LIVE_BASE_URL fetched: {DADDY_LIVE_BASE_URL}")
except requests.RequestException as e:
    app.logger.error(f"Failed to fetch DADDY_LIVE_BASE_URL: {e}")
    DADDY_LIVE_BASE_URL = "https://daddylive.sx/" # Fallback to a common Daddylive domain if fetching fails

# Regex for Daddylive.sx stream URLs (e.g., https://daddylive.sx/stream/stream-ID.php)
DADDY_LIVE_STREAM_PHP_PATTERN = re.compile(r"https?://(?:www\.)?daddylive\.sx/stream/stream-(\d+)\.php")

VAVOO_PROXY = os.getenv('VAVOO_PROXY', None)
VAVOO_SSL_VERIFY = os.getenv('VAVOO_SSL_VERIFY', 'false').lower() == 'true'
GENERAL_PROXY = os.getenv('GENERAL_PROXY', None)
GENERAL_SSL_VERIFY = os.getenv('GENERAL_SSL_VERIFY', 'false').lower() == 'true'

# Disabilita gli avvisi di richiesta non sicura se la verifica SSL è disattivata per QUALSIASI proxy
if not all([NEWKSO_SSL_VERIFY, VAVOO_SSL_VERIFY, GENERAL_SSL_VERIFY]):
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
DADDY_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'

def _get_proxy_dict(proxy_env_var):
    """Helper per creare un dizionario di proxy da una variabile d'ambiente."""
    if not proxy_env_var:
        return None
    proxy_list = [p.strip() for p in proxy_env_var.split(',')]
    selected_proxy = random.choice(proxy_list)
    # la libreria requests gestisce lo schema (http, https, socks5, socks5h) dall'URL del proxy
    return {'http': selected_proxy, 'https': selected_proxy}

def get_proxy_config_for_url(url):
    """
    Restituisce la configurazione del proxy (dizionario proxy e flag di verifica SSL) per un dato URL.
    Supporta proxy specifici per dominio (newkso, vavoo) e un proxy generale.
    """
    lower_url = url.lower()
    parsed_url = urlparse(lower_url)

    # 1. newkso.ru (per i domini specifici di newkso)
    is_newkso = "newkso.ru" in parsed_url.netloc
    if is_newkso and NEWKSO_PROXY:
        return {"proxies": _get_proxy_dict(NEWKSO_PROXY), "verify": NEWKSO_SSL_VERIFY}

    # 2. vavoo.to
    if "vavoo.to" in parsed_url.netloc and VAVOO_PROXY:
        return {"proxies": _get_proxy_dict(VAVOO_PROXY), "verify": VAVOO_SSL_VERIFY}

    # 3. Proxy Generale (se non corrisponde a domini specifici)
    if GENERAL_PROXY:
        return {"proxies": _get_proxy_dict(GENERAL_PROXY), "verify": GENERAL_SSL_VERIFY}

    # 4. Nessun proxy
    return {"proxies": None, "verify": True}

def detect_m3u_type(content):
    """Rileva se è un M3U (lista IPTV) o un M3U8 (flusso HLS)."""
    if "#EXTM3U" in content and "#EXTINF" in content:
        return "m3u8"
    return "m3u"

def extract_daddylive_stream(initial_daddylive_url, client_headers):
    """
    Extracts the final M3U8 stream URL and headers from a Daddylive.sx stream.php URL.
    Emulates the logic from plugin.video.daddylive/addon.py.
    """
    app.logger.info(f"Starting Daddylive stream extraction for: {initial_daddylive_url}")

    try:
        # Step 1: Request to initial stream.php page
        headers = {'User-Agent': DADDY_UA, 'Referer': DADDY_LIVE_BASE_URL, 'Origin': DADDY_LIVE_BASE_URL}
        
        proxy_config = get_proxy_config_for_url(initial_daddylive_url)
        response = requests.get(initial_daddylive_url, headers=headers, timeout=10,
                                proxies=proxy_config['proxies'], verify=proxy_config['verify'])
        response.raise_for_status()
        html_content = response.text

        # Step 2: Extract and request "Player 2" link
        player_2_match = re.search(r'<a[^>]*href="([^"]+)"[^>]*>\s*<button[^>]*>\s*Player\s*2\s*<\/button>', html_content)
        if not player_2_match:
            app.logger.error("Daddylive: No 'Player 2' link found.")
            raise ValueError("No 'Player 2' link found.")

        url2_path = player_2_match.group(1)
        url2 = urljoin(DADDY_LIVE_BASE_URL, url2_path) # Use urljoin for robustness
        url2 = url2.replace('//cast', '/cast') # Fix for potential double slash

        headers['Referer'] = url2
        headers['Origin'] = url2 # Origin should be the same as Referer for this step
        
        proxy_config = get_proxy_config_for_url(url2)
        response = requests.get(url2, headers=headers, timeout=10,
                                proxies=proxy_config['proxies'], verify=proxy_config['verify'])
        response.raise_for_status()
        html_content = response.text

        # Step 3: Extract and request main iframe URL
        iframe_match = re.search(r'iframe src="([^"]*)"', html_content)
        if not iframe_match:
            app.logger.error("Daddylive: No iframe src found in Player 2 page.")
            raise ValueError("No iframe src found.")
        
        iframe_url = iframe_match.group(1)
        # The iframe_url might be relative or absolute. Use urljoin with url2 as base.
        iframe_url = urljoin(url2, iframe_url)

        headers['Referer'] = iframe_url # Referer for the iframe page
        headers['Origin'] = urlparse(iframe_url).scheme + "://" + urlparse(iframe_url).netloc # Origin for the iframe page
        
        proxy_config = get_proxy_config_for_url(iframe_url)
        response = requests.get(iframe_url, headers=headers, timeout=10,
                                proxies=proxy_config['proxies'], verify=proxy_config['verify'])
        response.raise_for_status()
        html_content = response.text

        # Step 4: Extract dynamic parameters (channelKey, auth_ts, auth_rnd, auth_sig, auth_host, auth_php, host, server_lookup)
        channel_key = re.search(r'(?s) channelKey = \"([^"]*)"', html_content).group(1)
        auth_ts = base64.b64decode(re.search(r'(?s)c = atob\("([^"]*)"\)', html_content).group(1)).decode('utf-8')
        auth_rnd = base64.b64decode(re.search(r'(?s)d = atob\("([^"]*)"\)', html_content).group(1)).decode('utf-8')
        auth_sig = base64.b64decode(re.search(r'(?s)e = atob\("([^"]*)"\)', html_content).group(1)).decode('utf-8')
        auth_host = base64.b64decode(re.search(r'(?s)a = atob\("([^"]*)"\)', html_content).group(1)).decode('utf-8')
        auth_php = base64.b64decode(re.search(r'(?s)b = atob\("([^"]*)"\)', html_content).group(1)).decode('utf-8')
        host = re.search(r'(?s)m3u8 =.*?:.*?:.*?".*?".*?"([^"]*)"', html_content).group(1)
        server_lookup = re.search(r"n fetchWithRetry\(\s*'([^']*)'", html_content).group(1)

        # Step 5: Request authentication URL
        auth_sig_quoted = quote_plus(auth_sig)
        auth_url = f'{auth_host}{auth_php}?channel_id={channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig_quoted}'
        
        proxy_config = get_proxy_config_for_url(auth_url)
        requests.get(auth_url, headers=headers, timeout=10,
                     proxies=proxy_config['proxies'], verify=proxy_config['verify'])

        # Step 6: Request server key
        server_lookup_url = f"https://{urlparse(iframe_url).netloc}{server_lookup}{channel_key}"
        
        proxy_config = get_proxy_config_for_url(server_lookup_url)
        response = requests.get(server_lookup_url, headers=headers, timeout=10,
                                proxies=proxy_config['proxies'], verify=proxy_config['verify'])
        response.raise_for_status()
        server_key = response.json()['server_key']

        # Step 7: Construct final M3U8 link
        final_m3u8_url = f'https://{server_key}{host}{server_key}/{channel_key}/mono.m3u8'

        # Construct final headers for the M3U8 stream
        referer_raw = f'https://{urlparse(iframe_url).netloc}'
        final_headers = {
            'User-Agent': DADDY_UA,
            'Referer': referer_raw + '/',
            'Origin': referer_raw,
            'Connection': 'Keep-Alive'
        }
        
        app.logger.info(f"Daddylive: Successfully extracted M3U8 URL: {final_m3u8_url}")
        return {"resolved_url": final_m3u8_url, "headers": final_headers}

    except (requests.RequestException, ValueError, KeyError, AttributeError) as e:
        app.logger.error(f"Daddylive extraction failed for {initial_daddylive_url}: {e}", exc_info=True)
        return {"resolved_url": None, "headers": {}} # Return None for resolved_url on failure
    except Exception as e:
        app.logger.error(f"Daddylive unexpected extraction error for {initial_daddylive_url}: {e}", exc_info=True)
        return {"resolved_url": None, "headers": {}} # Return None for resolved_url on failure

def resolve_m3u8_link(url, headers=None):
    """
    Risolve un URL M3U8 supportando header e proxy per newkso.ru e daddy_php_sites.
    """
    if not url:
        app.logger.error("URL non fornito.")
        return {"resolved_url": None, "headers": {}}

    app.logger.info(f"Tentativo di risoluzione URL: {url}")

    # Inizializza gli header di default
    current_headers = headers if headers else {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
    }
    
    clean_url = url
    extracted_headers = {}

    # Estrazione header da URL
    if '&h_' in url or '%26h_' in url:
        app.logger.info("Rilevati parametri header nell'URL - Estrazione in corso...")
        if '%26h_' in url:
            if 'vavoo.to' in url.lower():
                url = url.replace('%26', '&')
            else:
                url = unquote(unquote(url))
        url_parts = url.split('&h_', 1)
        clean_url = url_parts[0]
        header_params = '&h_' + url_parts[1]
        for param in header_params.split('&'):
            if param.startswith('h_'):
                try:
                    key_value = param[2:].split('=', 1)
                    if len(key_value) == 2:
                        key = unquote(key_value[0]).replace('_', '-')
                        value = unquote(key_value[1])
                        extracted_headers[key] = value
                except Exception as e:
                    app.logger.error(f"Errore nell'estrazione dell'header {param}: {e}")
        current_headers.update(extracted_headers)
    else:
        app.logger.info("URL pulito rilevato - Nessuna estrazione header necessaria")

    # Check if it's a Daddylive.sx stream.php URL and use the specific extractor
    if DADDY_LIVE_STREAM_PHP_PATTERN.match(clean_url):
        app.logger.info(f"Detected Daddylive.sx stream.php URL: {clean_url}. Using specific extractor.")
        return extract_daddylive_stream(clean_url, current_headers)

    # Fallback: richiesta normale
    try:
        with requests.Session() as session:
            proxy_config = get_proxy_config_for_url(clean_url)
            if proxy_config['proxies']:
                app.logger.debug(f"Proxy in uso per {clean_url}")
            app.logger.info(f"Passo 1: Richiesta a {clean_url}")
            response = session.get(clean_url, headers=current_headers, proxies=proxy_config['proxies'], 
                                 allow_redirects=True, timeout=(10, 20), verify=proxy_config['verify'])
            response.raise_for_status()
            initial_response_text = response.text
            final_url_after_redirects = response.url
            app.logger.info(f"Passo 1 completato. URL finale dopo redirect: {final_url_after_redirects}")

            if initial_response_text and initial_response_text.strip().startswith('#EXTM3U'):
                app.logger.info("Trovato file M3U8 diretto.")
                return {
                    "resolved_url": final_url_after_redirects,
                    "headers": current_headers
                }
            else:
                app.logger.info("La risposta iniziale non era un M3U8 diretto.")
                return {
                    "resolved_url": clean_url,
                    "headers": current_headers
                }

    except requests.RequestException as e:
        app.logger.error(f"Errore durante la richiesta HTTP iniziale: {e}")
        return {"resolved_url": clean_url, "headers": current_headers}
    except Exception as e:
        app.logger.error(f"Errore generico durante la risoluzione: {e}")
        return {"resolved_url": clean_url, "headers": current_headers}

@app.route('/proxy')
def proxy():
    """Proxy per liste M3U che aggiunge automaticamente /proxy/m3u?url= con IP prima dei link"""
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    try:
        server_ip = request.host
        response = requests.get(m3u_url, timeout=(10, 30))
        response.raise_for_status()
        m3u_content = response.text
        
        modified_lines = []
        # This list will accumulate header parameters for the *next* stream URL
        current_stream_headers_params = [] 

        for line in m3u_content.splitlines():
            line = line.strip()
            if line.startswith('#EXTHTTP:'):
                try:
                    json_str = line.split(':', 1)[1].strip()
                    headers_dict = json.loads(json_str)
                    for key, value in headers_dict.items():
                        encoded_key = quote(quote(key))
                        encoded_value = quote(quote(str(value)))
                        current_stream_headers_params.append(f"h_{encoded_key}={encoded_value}")
                except Exception as e:
                    app.logger.error(f"Errore nel parsing di #EXTHTTP '{line}': {e}")
                modified_lines.append(line)
            
            elif line.startswith('#EXTVLCOPT:'):
                try:
                    options_str = line.split(':', 1)[1].strip()
                    # Split by comma, then iterate through key=value pairs
                    for opt_pair in options_str.split(','):
                        opt_pair = opt_pair.strip()
                        if '=' in opt_pair:
                            key, value = opt_pair.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"') # Remove potential quotes
                            
                            header_key = None
                            if key.lower() == 'http-user-agent':
                                header_key = 'User-Agent'
                            elif key.lower() == 'http-referer':
                                header_key = 'Referer'
                            elif key.lower() == 'http-cookie':
                                header_key = 'Cookie'
                            elif key.lower() == 'http-header': # For generic http-header option
                                # This handles cases like http-header=X-Custom: Value
                                full_header_value = value
                                if ':' in full_header_value:
                                    header_name, header_val = full_header_value.split(':', 1)
                                    header_key = header_name.strip()
                                    value = header_val.strip()
                                else:
                                    app.logger.warning(f"Malformed http-header option in EXTVLCOPT: {opt_pair}")
                                    continue # Skip malformed header
                            
                            if header_key:
                                encoded_key = quote(quote(header_key))
                                encoded_value = quote(quote(value))
                                current_stream_headers_params.append(f"h_{encoded_key}={encoded_value}")
                            
                except Exception as e:
                    app.logger.error(f"Errore nel parsing di #EXTVLCOPT '{line}': {e}")
                modified_lines.append(line) # Keep the original EXTVLCOPT line in the output
            elif line and not line.startswith('#'):
                if 'pluto.tv' in line.lower():
                    modified_lines.append(line)
                else:
                    encoded_line = quote(line, safe='')
                    # Construct the headers query string from accumulated parameters
                    headers_query_string = ""
                    if current_stream_headers_params:
                        headers_query_string = "%26" + "%26".join(current_stream_headers_params)
                    
                    modified_line = f"http://{server_ip}/proxy/m3u?url={encoded_line}{headers_query_string}"
                    modified_lines.append(modified_line)
                
                # Reset headers for the next stream URL
                current_stream_headers_params = [] 
            else:
                modified_lines.append(line)
        
        modified_content = '\n'.join(modified_lines)
        parsed_m3u_url = urlparse(m3u_url)
        original_filename = os.path.basename(parsed_m3u_url.path)
        
        return Response(modified_content, content_type="application/vnd.apple.mpegurl", headers={'Content-Disposition': f'attachment; filename="{original_filename}"'})
        
    except requests.RequestException as e:
        return f"Errore durante il download della lista M3U: {str(e)}", 500
    except Exception as e:
        return f"Errore generico: {str(e)}", 500

@app.route('/proxy/m3u')
def proxy_m3u():
    """Proxy per file M3U e M3U8 con supporto per proxy e caching."""
    m3u_url = request.args.get('url', '').strip()
    if not m3u_url:
        return "Errore: Parametro 'url' mancante", 400

    # Crea una chiave univoca per la cache basata sull'URL e sugli header specifici
    # Questo assicura che richieste con header diversi non usino la stessa cache
    cache_key_headers = "&".join(sorted([f"{k}={v}" for k, v in request.args.items() if k.lower().startswith("h_")]))
    cache_key = f"{m3u_url}|{cache_key_headers}"

    # Controlla se la risposta è già in cache
    if cache_key in M3U8_CACHE:
        app.logger.info(f"Cache HIT per M3U8: {m3u_url}")
        cached_response = M3U8_CACHE[cache_key]
        return Response(cached_response, content_type="application/vnd.apple.mpegurl; charset=utf-8")
    
    app.logger.info(f"Cache MISS per M3U8: {m3u_url}")

    default_headers = {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/33.0 Mobile/15E148 Safari/605.1.15",
        "Referer": "https://vavoo.to/",
        "Origin": "https://vavoo.to"
    }

    request_headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }
    
    headers = {**default_headers, **request_headers}

    processed_url = m3u_url

    try:
        result = resolve_m3u8_link(processed_url, headers)

        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL in un M3U8 valido.", 500

        resolved_url = result["resolved_url"]
        current_headers_for_proxy = result["headers"]

        proxy_config = get_proxy_config_for_url(resolved_url)
        if proxy_config['proxies']:
            app.logger.debug(f"Proxy in uso per GET {resolved_url}")

        m3u_response = requests.get(resolved_url, headers=current_headers_for_proxy, 
                                   proxies=proxy_config['proxies'], allow_redirects=True, timeout=(10, 20),
                                   verify=proxy_config['verify'])
        m3u_response.raise_for_status()
        m3u_response.encoding = m3u_response.apparent_encoding or 'utf-8'
        m3u_content = m3u_response.text
        final_url = m3u_response.url

        file_type = detect_m3u_type(m3u_content)

        if file_type == "m3u":
            return Response(m3u_content, content_type="application/vnd.apple.mpegurl; charset=utf-8")

        parsed_url = urlparse(final_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path.rsplit('/', 1)[0]}/"

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
        
        # Salva il contenuto modificato nella cache prima di restituirlo
        M3U8_CACHE[cache_key] = modified_m3u8_content
        
        return Response(modified_m3u8_content, content_type="application/vnd.apple.mpegurl; charset=utf-8")

    except requests.RequestException as e:
        return f"Errore durante il download o la risoluzione del file: {str(e)}", 500
    except Exception as e:
        return f"Errore generico nella funzione proxy_m3u: {str(e)}", 500

@app.route('/proxy/ts')
def proxy_ts():
    """Proxy per segmenti .TS con caching, headers personalizzati e supporto proxy."""
    ts_url = request.args.get('url', '').strip()
    if not ts_url:
        return "Errore: Parametro 'url' mancante", 400

    # Controlla se il segmento è in cache
    if ts_url in TS_CACHE:
        app.logger.info(f"Cache HIT per TS: {ts_url}")
        # Restituisce il contenuto direttamente dalla cache
        return Response(TS_CACHE[ts_url], content_type="video/mp2t")

    app.logger.info(f"Cache MISS per TS: {ts_url}")

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    proxy_config = get_proxy_config_for_url(ts_url)
    if proxy_config['proxies']:
        app.logger.debug(f"Proxy in uso per {ts_url}")

    try:
        # Nota: stream=False per scaricare l'intero segmento e poterlo mettere in cache
        response = requests.get(ts_url, headers=headers, proxies=proxy_config['proxies'], stream=False, allow_redirects=True, timeout=(10, 30), verify=proxy_config['verify'])
        response.raise_for_status()
        
        ts_content = response.content
        
        # Salva il contenuto del segmento nella cache
        if ts_content:
            TS_CACHE[ts_url] = ts_content
        
        return Response(ts_content, content_type="video/mp2t")
    
    except requests.RequestException as e:
        return f"Errore durante il download del segmento TS: {str(e)}", 500

@app.route('/proxyd')
def proxyd():
    """
    Endpoint per proxyare i link di Daddylive.sx.
    Estrae il link M3U8 effettivo e reindirizza a /proxy/m3u.
    """
    daddylive_url = request.args.get('url', '').strip()
    if not daddylive_url:
        return "Errore: Parametro 'url' mancante per Daddylive.", 400

    app.logger.info(f"Received Daddylive proxy request for: {daddylive_url}")

    try:
        # Extract the final M3U8 URL and headers
        extracted_info = extract_daddylive_stream(daddylive_url, request.headers)
        final_m3u8_url = extracted_info["resolved_url"]
        final_headers = extracted_info["headers"]

        if not final_m3u8_url:
            app.logger.error(f"Daddylive extraction returned no URL for {daddylive_url}")
            return "Errore: Impossibile estrarre il link Daddylive.", 500

        # Redirect to /proxy/m3u with the extracted URL and headers
        headers_query_string = "&".join([f"h_{quote(k)}={quote(v)}" for k, v in final_headers.items()])
        return_url = f"/proxy/m3u?url={quote(final_m3u8_url)}&{headers_query_string}"
        return Response(status=302, headers={'Location': return_url})
    except Exception as e:
        app.logger.error(f"Error processing Daddylive proxy request for {daddylive_url}: {e}", exc_info=True)
        return f"Errore durante l'elaborazione del link Daddylive: {str(e)}", 500

@app.route('/')
def index():
    """Pagina principale che mostra un messaggio di benvenuto"""
    return "Proxy started!"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=7860, debug=False)
