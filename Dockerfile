# Usa l'immagine base di Python
FROM python:3.12-slim

# Imposta la directory di lavoro
WORKDIR /app

# Copia i file necessari
COPY requirements.txt .
COPY app.py .

# Installa le dipendenze
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Installa Gunicorn (se non è già in requirements.txt)
RUN pip install gunicorn

# Espone la porta 7860 per Flask/Gunicorn
EXPOSE 7860

# Comando per avviare il server Flask con Gunicorn e 4 worker
CMD ["gunicorn", "app:app", \
     "-w", "4", \
     "--worker-class", "gevent", \
     "--worker-connections", "100", \
     "-b", "0.0.0.0:7860", \
     "--timeout", "120", \
     "--keep-alive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100"]