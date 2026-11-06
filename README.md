# Projeto Aplicado: Práticas de Mercado — Protótipo web seguro

App Flask com **Login → Painel interno → Logout**, hospedado em VM Ubuntu Server (Nginx + gunicorn + HTTPS por IP) e implantado via **GitHub Actions**.

Fluxo: Antigravity (dev) → `git push origin main` → GitHub Actions → rsync/SSH → VM.

## Eixo 3 — 3 categorias OWASP Top 10:2025 mitigadas
| Categoria | Onde / como (`app.py`) |
|---|---|
| **A01 Broken Access Control** | `@login_required` protege `/dashboard`; sem sessão autenticada redireciona ao login. |
| **A07 Authentication Failures** | Senha só como hash (scrypt, `check_password_hash`); limite de 5 tentativas/5 min por IP; mensagem de erro genérica; `session.clear()` no login (anti-fixation); cookie `HttpOnly`, `Secure`, `SameSite=Strict`; sessão expira em 30 min; token CSRF em login/logout. |
| **A05 Injection** | Jinja2 com autoescape (anti-XSS), entradas com limite de tamanho, nenhuma consulta SQL/shell com dados do usuário, CSP restritiva. |

Extras: cabeçalhos de segurança (A02), segredos só em variáveis de ambiente (`/etc/projeto.env` no servidor, fora do Git).

## Infraestrutura (Eixo 1)
- Ubuntu Server (última LTS), Nginx, login SSH só por chave, senha desabilitada.
- UFW/Security Group: apenas 22, 80, 443. Fail2Ban no SSH: 4 erros = ban 24h.
- HTTPS: Certbot ≥ 5.4 com certificado Let's Encrypt para IP, renovação automática, redirect 80→443.
- SSL Labs: nota A + PQC (`X25519MLKEM768`) — _anexar print aqui_.

## Repositório (Eixo 2)
`.gitignore` bloqueia `.env`, chaves, bancos. Credenciais do deploy ficam em **Settings → Secrets → Actions**: `SSH_PRIVATE_KEY`, `SSH_HOST`, `SSH_USER`.

## Como rodar local
```
python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt
python -c "from werkzeug.security import generate_password_hash as g; print(g('SUA_SENHA'))"
export SECRET_KEY=$(python -c "import secrets;print(secrets.token_hex(32))") APP_USER=admin APP_PASSWORD_HASH='<hash>' COOKIE_SECURE=0
flask --app app run
```
