from flask import Flask, request, Response
import requests
from urllib.parse import urlparse, urljoin, quote, unquote
import re
import traceback

app = Flask(__name__)

def detect_m3u_type(content):
    """ Rileva se è un M3U (lista IPTV) o un M3U8 (flusso HLS) """
    if "#EXTM3U" in content and "#EXTINF" in content:
        return "m3u8"
    return "m3u"

def replace_key_uri(line, headers_query):
    """ Sostituisce l'URI della chiave AES-128 con il proxy """
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
            # Primo passo: Richiesta all'URL iniziale
            print(f"Passo 1: Richiesta a {url}")
            response = session.get(url, headers=current_headers, allow_redirects=True, timeout=10)
            response.raise_for_status() # Solleva un'eccezione per risposte con stato di errore (4xx o 5xx)
            initial_response_text = response.text
            final_url_after_redirects = response.url # Mantieni questo per debug se necessario
            print(f"Passo 1 completato. URL finale dopo redirect: {final_url_after_redirects}")

            # Prova la logica dell'iframe
            print("Tentativo con logica iframe...")
            try:
                # Secondo passo (Iframe): Trova l'iframe src nella risposta iniziale
                iframes = re.findall(r'iframe src="([^"]+)', initial_response_text)
                if not iframes:
                    # Se non trova l'iframe, solleva un'eccezione per passare al fallback
                    raise ValueError("Nessun iframe src trovato.")

                url2 = iframes[0]
                print(f"Passo 2 (Iframe): Trovato iframe URL: {url2}")

                # Terzo passo (Iframe): Richiesta all'URL dell'iframe
                # Aggiorna Referer e Origin per la richiesta all'iframe
                referer_raw = urlparse(url2).scheme + "://" + urlparse(url2).netloc + "/"
                origin_raw = urlparse(url2).scheme + "://" + urlparse(url2).netloc
                current_headers['Referer'] = referer_raw
                current_headers['Origin'] = origin_raw
                print(f"Passo 3 (Iframe): Richiesta a {url2}")
                response = session.get(url2, headers=current_headers, timeout=10)
                response.raise_for_status()
                iframe_response_text = response.text
                print("Passo 3 (Iframe) completato.")

                # Quarto passo (Iframe): Estrai parametri dinamici dall'iframe response
                channel_key_match = re.search(r'(?s) channelKey = \"([^"]*)', iframe_response_text)
                auth_ts_match = re.search(r'(?s) authTs\s*= \"([^"]*)', iframe_response_text)
                auth_rnd_match = re.search(r'(?s) authRnd\s*= \"([^"]*)', iframe_response_text)
                auth_sig_match = re.search(r'(?s) authSig\s*= \"([^"]*)', iframe_response_text)
                auth_host_match = re.search(r'\}\s*fetchWithRetry\(\s*\'([^\']*)', iframe_response_text)
                # Estrai anche il parametro per la server lookup URL
                server_lookup_match = re.search('n fetchWithRetry\(\s*\'([^\']*)', iframe_response_text)

                if not all([channel_key_match, auth_ts_match, auth_rnd_match, auth_sig_match, auth_host_match, server_lookup_match]):
                     raise ValueError("Impossibile estrarre tutti i parametri dinamici dall'iframe response.")

                channel_key = channel_key_match.group(1)
                auth_ts = auth_ts_match.group(1)
                auth_rnd = auth_rnd_match.group(1)
                auth_sig = quote(auth_sig_match.group(1)) # Codifica auth_sig
                auth_host = auth_host_match.group(1)
                server_lookup = server_lookup_match.group(1) # Parametro per la server lookup URL

                print("Passo 4 (Iframe): Parametri dinamici estratti.")

                # Quinto passo (Iframe): Richiesta di autenticazione
                auth_url = f'{auth_host}{channel_key}&ts={auth_ts}&rnd={auth_rnd}&sig={auth_sig}'
                print(f"Passo 5 (Iframe): Richiesta di autenticazione a {auth_url}")
                auth_response = session.get(auth_url, headers=current_headers, timeout=10)
                auth_response.raise_for_status()
                print("Passo 5 (Iframe) completato.")

                # Sesto passo (Iframe): Richiesta di server lookup per ottenere la server_key
                server_lookup_url = f"https://{urlparse(url2).netloc}{server_lookup}{channel_key}"
                print(f"Passo 6 (Iframe): Richiesta server lookup a {server_lookup_url}")
                server_lookup_response = session.get(server_lookup_url, headers=current_headers, timeout=10)
                server_lookup_response.raise_for_status()
                server_lookup_data = server_lookup_response.json() # Assumiamo che la risposta sia JSON
                print("Passo 6 (Iframe) completato.")

                # Settimo passo (Iframe): Estrai server_key dalla risposta di server lookup
                server_key = server_lookup_data.get('server_key')
                if not server_key:
                    raise ValueError("'server_key' non trovato nella risposta di server lookup.")
                print(f"Passo 7 (Iframe): Estratto server_key: {server_key}")

                # Ottavo passo (Iframe): Costruisci il link finale
                # Trova l'host finale per l'm3u8 (potrebbe essere diverso da auth_host)
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
                    'Origin': origin_raw # Usa origin_raw qui
                }
                
                return {
                    "resolved_url": final_stream_url,
                    "headers": stream_headers
                }

            except (ValueError, requests.exceptions.RequestException) as e:
                # Se la logica iframe fallisce, prova il fallback
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
                        "resolved_url": url,  # Restituisci l'URL originale in caso di fallimento
                        "headers": current_headers
                    }

    except requests.exceptions.RequestException as e:
        print(f"Errore durante la richiesta HTTP iniziale: {e}")
        print(f"Dettagli errore: {traceback.format_exc()}")
        return {"resolved_url": url, "headers": current_headers}
    except Exception as e:
        print(f"Errore generico durante la risoluzione: {e}")
        print(f"Dettagli errore: {traceback.format_exc()}")
        return {"resolved_url": url, "headers": current_headers}

@app.route('/proxy/m3u')
def proxy_m3u():
    """ Proxy per file M3U e M3U8 con supporto per redirezioni e header personalizzati """
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

    # --- Nuova logica per trasformare l'URL se necessario ---
    processed_url = m3u_url
    # Controlla se l'URL termina con /mono.m3u8 e contiene /premiumXXX/
    # La regex cerca il pattern alla fine della stringa ($)
    match_premium_m3u8 = re.search(r'/premium(\d+)/mono\.m3u8$', m3u_url)

    if match_premium_m3u8:
        channel_number = match_premium_m3u8.group(1)
        transformed_url = f"https://daddylive.dad/embed/stream-{channel_number}.php"
        print(f"URL {m3u_url} corrisponde al pattern premium. Trasformato in: {transformed_url}")
        processed_url = transformed_url
    else:
        print(f"URL {m3u_url} non corrisponde al pattern premium/mono.m3u8. Utilizzo URL originale.")
    # --- Fine nuova logica ---

    try:
        # Chiama sempre la funzione di risoluzione con l'URL processato (trasformato o originale)
        print(f"Chiamata a resolve_m3u8_link per URL processato: {processed_url}")
        result = resolve_m3u8_link(processed_url, headers)

        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL in un M3U8 valido.", 500

        resolved_url = result["resolved_url"]
        current_headers_for_proxy = result["headers"] # Usa gli header dalla risoluzione

        print(f"Risoluzione completata. URL M3U8 finale: {resolved_url}")

        # Fetchare il contenuto M3U8 effettivo dall'URL risolto
        print(f"Fetching M3U8 content from resolved URL: {resolved_url}")
        m3u_response = requests.get(resolved_url, headers=current_headers_for_proxy, allow_redirects=True, timeout=10)
        m3u_response.raise_for_status()
        m3u_content = m3u_response.text
        final_url = m3u_response.url # Aggiorna final_url all'URL M3U8 effettivo

        # Ora processa il contenuto M3U8 (sempre risolto)
        file_type = detect_m3u_type(m3u_content)

        if file_type == "m3u":
            # Gestisci playlist M3U (non stream M3U8)
            return Response(m3u_content, content_type="audio/x-mpegurl")

        # Processa contenuto M3U8
        parsed_url = urlparse(final_url)
        # Determina l'URL base per i percorsi relativi nell'M3U8
        # Usa la directory dell'URL M3U8 finale
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path.rsplit('/', 1)[0]}/"

        # Prepara la query degli header per segmenti/chiavi proxati
        headers_query = "&".join([f"h_{quote(k)}={quote(v)}" for k, v in current_headers_for_proxy.items()])

        modified_m3u8 = []
        for line in m3u_content.splitlines():
            line = line.strip()
            if line.startswith("#EXT-X-KEY") and 'URI="' in line:
                line = replace_key_uri(line, headers_query)
            elif line and not line.startswith("#"):
                # Gestisci URL di segmenti relativi e assoluti
                segment_url = urljoin(base_url, line)
                line = f"/proxy/ts?url={quote(segment_url)}&{headers_query}"
            modified_m3u8.append(line)

        modified_m3u8_content = "\n".join(modified_m3u8)

        return Response(modified_m3u8_content, content_type="application/vnd.apple.mpegurl")

    except requests.RequestException as e:
        print(f"Errore durante il download o la risoluzione del file: {str(e)}")
        print(f"Dettagli errore: {traceback.format_exc()}")
        return f"Errore durante il download o la risoluzione del file M3U/M3U8: {str(e)}", 500
    except Exception as e:
        print(f"Errore generico nella funzione proxy_m3u: {str(e)}")
        print(f"Dettagli errore: {traceback.format_exc()}")
        return f"Errore generico durante l'elaborazione: {str(e)}", 500

@app.route('/proxy/resolve')
def proxy_resolve():
    """ Proxy per risolvere e restituire un URL M3U8 """
    url = request.args.get('url', '').strip()
    if not url:
        return "Errore: Parametro 'url' mancante", 400

    # Estrai gli header dalla richiesta
    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    try:
        # Risolvi l'URL usando la funzione di risoluzione
        result = resolve_m3u8_link(url, headers)
        
        if not result["resolved_url"]:
            return "Errore: Impossibile risolvere l'URL", 500
            
        # Costruisci la query per gli header
        headers_query = "&".join([f"h_{quote(k)}={quote(v)}" for k, v in result["headers"].items()])
        
        # Reindirizza al proxy M3U8 con l'URL risolto
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
    """ Proxy per segmenti .TS con headers personalizzati """
    ts_url = request.args.get('url', '').strip()
    if not ts_url:
        return "Errore: Parametro 'url' mancante", 400

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    try:
        response = requests.get(ts_url, headers=headers, stream=True, allow_redirects=True)
        response.raise_for_status()
        return Response(response.iter_content(chunk_size=1024), content_type="video/mp2t")
    
    except requests.RequestException as e:
        return f"Errore durante il download del segmento TS: {str(e)}", 500

@app.route('/proxy/key')
def proxy_key():
    """ Proxy per la chiave AES-128 con header personalizzati """
    key_url = request.args.get('url', '').strip()
    if not key_url:
        return "Errore: Parametro 'url' mancante per la chiave", 400

    headers = {
        unquote(key[2:]).replace("_", "-"): unquote(value).strip()
        for key, value in request.args.items()
        if key.lower().startswith("h_")
    }

    try:
        response = requests.get(key_url, headers=headers, allow_redirects=True)
        response.raise_for_status()
        return Response(response.content, content_type="application/octet-stream")
    
    except requests.RequestException as e:
        return f"Errore durante il download della chiave AES-128: {str(e)}", 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=7860, debug=False)
