# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y gcc libpq-dev && rm -rf /var/lib/apt/lists/*

# Copiar requirements e instalar
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código da aplicação
COPY . ./app/

# Expor porta da aplicação
EXPOSE 5000

# Comando para rodar a aplicação
CMD ["python3", "app/main.py"]
