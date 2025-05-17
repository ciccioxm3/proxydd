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

# Espone la porta 7860 per Flask
EXPOSE 7860

# Comando per avviare il server Flask
CMD ["python", "app.py"]
