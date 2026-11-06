#!/usr/bin/env bash
# Rodar como root na VM (Ubuntu Server) APÓS configurar login por chave SSH.
set -euo pipefail
apt update && apt -y upgrade
apt -y install nginx fail2ban ufw python3-venv rsync snapd

# SSH: só chave
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart ssh

# Firewall (também feche tudo além de 22/80/443 no Security Group da nuvem)
ufw default deny incoming; ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw --force enable

# Fail2Ban: 4 erros -> ban de 24h
cat > /etc/fail2ban/jail.d/sshd.local <<'J'
[sshd]
enabled = true
maxretry = 4
bantime = 86400
J
systemctl restart fail2ban

# Usuário de deploy + app
id deploy &>/dev/null || adduser --disabled-password --gecos "" deploy
mkdir -p /opt/projeto/app && chown -R deploy: /opt/projeto
sudo -u deploy python3 -m venv /opt/projeto/venv
echo 'deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart projeto' > /etc/sudoers.d/deploy
echo ">> Coloque a chave PÚBLICA do deploy em /home/deploy/.ssh/authorized_keys"
echo ">> Crie /etc/projeto.env (chmod 600) com SECRET_KEY, APP_USER, APP_PASSWORD_HASH"
echo ">> Copie deploy/projeto.service para /etc/systemd/system/ e deploy/nginx.conf para /etc/nginx/sites-available/default"

# Certbot >= 5.4 (via snap)
snap install --classic certbot && ln -sf /snap/bin/certbot /usr/bin/certbot
certbot --version
