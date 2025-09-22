# Escolha uma imagem oficial Python minimalista
FROM python:3.11-slim

# Evita geração de arquivos .pyc e ativa buffer sem bloqueios de I/O
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Diretório de trabalho dentro do contêiner
WORKDIR /app

# Copia e instala as dependências do projeto
COPY flask_app/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copia o código da aplicação para o contêiner
COPY flask_app/ /app

# Exponha a porta 5000 (útil para testes locais; Render usará a PORT fornecida)
EXPOSE 5000

# Comando para iniciar o servidor WSGI (Gunicorn) usando a variável PORT do Render
CMD ["sh", "-c", "gunicorn -b 0.0.0.0:${PORT:-5000} app:create_app()"]
