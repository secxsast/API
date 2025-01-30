FROM ubuntu:latest

# ❌ Mala práctica: Exponer credenciales en variables de entorno
ENV AWS_ACCESS_KEY_ID="AKIAEXAMPLESECRET"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ❌ Mala práctica: Usar credenciales en comandos RUN
RUN echo "my-secret-password" | some-command

# ❌ Mala práctica: Copiar archivos con credenciales
COPY config.json /etc/config.json