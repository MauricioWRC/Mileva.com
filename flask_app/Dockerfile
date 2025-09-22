# Use uma imagem oficial Python
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Diretório de trabalho
WORKDIR /app

# Copia e instala as dependências
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copia todo o código-fonte (incluindo templates e static)
COPY . /app

# Exponha a porta 5000 para testes locais (Render usa o PORT automaticamente)
EXPOSE 5000

# Inicia a aplicação com gunicorn, usando a variável PORT do Render se existir
CMD ["sh", "-c", "gunicorn -b 0.0.0.0:${PORT:-5000} app:create_app()"]
