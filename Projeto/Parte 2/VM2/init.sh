#!/bin/bash

# Script para configurar servidor de backup na VM2
# Backup dos diretórios da VM1 + dados próprios

set -e

echo "[+] Configurando servidor de backup na VM2..."

# Diretórios na VM2
BACKUP_BASE="/backup-storage"
VM1_BACKUPS="$BACKUP_BASE/vm1-backups"
VM2_DATA="$BACKUP_BASE/vm2-data"
SCRIPTS_DIR="$BACKUP_BASE/scripts"
LOGS_DIR="$BACKUP_BASE/logs"

# Criar estrutura de diretórios
mkdir -p $VM1_BACKUPS $VM2_DATA $SCRIPTS_DIR $LOGS_DIR

# Instalar dependências
echo "[+] Instalando dependências..."
apt-get update && apt-get install -y \
    rsync \
    openssh-server \
    postgresql-client \
    mysql-client \
    python3 \
    python3-pip \
    curl \
    wget \
    unzip \
    git \
    jq

# Configurar SSH para acesso à VM1
echo "[+] Configurando SSH..."
mkdir -p /root/.ssh
ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N ""

# Criar script de backup automático da VM1
cat > $SCRIPTS_DIR/backup-vm1.sh << 'EOF'
#!/bin/bash
# Script de backup automático da VM1

VM1_IP="192.168.100.5"
VM1_USER="vm1"  # Ajuste conforme o usuário da VM1
SSH_KEY="/root/.ssh/id_rsa"
BACKUP_DIR="/backup-storage/vm1-backups"
LOG_FILE="/backup-storage/logs/backup-$(date +%Y%m%d).log"

echo "[$(date)] Iniciando backup da VM1..." >> $LOG_FILE

# 1. Backup do diretório /opt/.system-backup-2025 da VM1
echo "[$(date)] Backup do diretório system-backup..." >> $LOG_FILE
rsync -avz -e "ssh -i $SSH_KEY -o StrictHostKeyChecking=no" \
    $VM1_USER@$VM1_IP:/opt/.system-backup-2025/ \
    $BACKUP_DIR/system-backup/ >> $LOG_FILE 2>&1

# 2. Backup do diretório da aplicação /home/vm1/Downloads/Projeto
echo "[$(date)] Backup do diretório da aplicação..." >> $LOG_FILE
rsync -avz -e "ssh -i $SSH_KEY -o StrictHostKeyChecking=no" \
    $VM1_USER@$VM1_IP:/home/vm1/Downloads/Projeto/ \
    $BACKUP_DIR/app-source/ >> $LOG_FILE 2>&1

# 3. Backup do banco de dados PostgreSQL da VM1
echo "[$(date)] Backup do banco de dados..." >> $LOG_FILE
ssh -i $SSH_KEY -o StrictHostKeyChecking=no $VM1_USER@$VM1_IP \
    "PGPASSFILE=/home/vm1/.pgpass pg_dump -U vulnuser -h localhost -d vulndb" > \
    $BACKUP_DIR/database/vulndb-$(date +%Y%m%d).sql 2>> $LOG_FILE

echo "[$(date)] Backup concluído" >> $LOG_FILE

# Limitar retenção para 7 dias
find $BACKUP_DIR -name "*.sql" -mtime +7 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
EOF

chmod +x $SCRIPTS_DIR/backup-vm1.sh

# Criar estrutura de diretórios para backups da VM1
mkdir -p $VM1_BACKUPS/{system-backup,app-source,database,system-configs,logs}

# Simular dados do backup da VM1 (já que não temos acesso real ainda)
echo "[+] Gerando dados simulados do backup da VM1..."

# 1. Simular conteúdo do /opt/.system-backup-2025 da VM1
cat > $VM1_BACKUPS/system-backup/readme.txt << 'EOF'
=== BACKUP DO SISTEMA VM1 - CONFIDENCIAL ===

Este diretório contém backups automáticos do sistema VM1.

Arquivos incluídos:
- Configurações de serviços
- Logs do sistema
- Chaves de criptografia
- Backup de banco de dados
EOF

# Criar arquivos de backup "sensíveis"
cat > $VM1_BACKUPS/system-backup/database-backup.sql << 'EOF'
-- BACKUP COMPLETO DO BANCO - VM1
-- Gerado em: 2025-11-01

-- Tabela de usuários com senhas (hashed)
CREATE TABLE vm2s (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50),
    password_hash VARCHAR(255),
    email VARCHAR(100),
    role VARCHAR(20)
);

INSERT INTO vm2s VALUES
(1, 'backup_admin', '$2y$10$8sA6N8H5h5Y1VfRkC9KJZeR9cL8M1S2N3B4V5C6X7Y8Z9A0B1C2D3E4F5G6H7I8J9', 'backup@corporacao.com', 'admin'),
(2, 'system_user', '$2y$10$9tB7O9I6i6Z2WgSdL0LKaSeT0M9N2T3O4C5W6D7Y8Z9A0B1C2D3E4F5G6H7I8J9', 'system@corporacao.com', 'system');

-- Configurações do sistema
CREATE TABLE system_config (
    config_key VARCHAR(100),
    config_value TEXT
);

INSERT INTO system_config VALUES
('secret_key', 'Vm1TdjNuMW50M3JOMWwwczNMMzRIM3I='),
('api_key', 'cHJvZHVjdGlvbl9hcGlfa2V5XzEyMzQ1Njc4OTA='),
('encryption_key', 'M2Q4ZjY2ZGMtOGUzMi00MTk1LThiMzYtZDRmMjY4ZmQ2OTg2');
EOF

# Chaves (simuladas)
cat > $VM1_BACKUPS/system-backup/ssh-keys.txt << 'EOF'
=== CHAVES SSH - CONFIDENCIAL ===

Chave para servidor de produção:
ssh-rsa AAAAB3NzaC1yc2E... vm1-backup-key

Chave para banco de dados:
ssh-rsa AAAAB3NzaC1yc2E... db-access-key

Chave para storage S3:
ssh-rsa AAAAB3NzaC1yc2E... s3-backup-key
EOF

# 2. Simular conteúdo do diretório da aplicação /home/vm1/Downloads/Projeto
cat > $VM1_BACKUPS/app-source/README.md << 'EOF'
# Aplicação Web - Corporação

## Estrutura do Projeto
- `/app` - Código fonte da aplicação Flask
- `/config` - Configurações e credenciais
- `/database` - Scripts e migrações do banco
- `/docs` - Documentação interna

## Credenciais de Desenvolvimento
- DB: postgresql://dev_user:DevPass123!@localhost:5432/dev_db
- API Key: sk_test_1234567890abcdef
- Secret: corp_dev_secret_2024
EOF

# 2. Gerar dados próprios da VM2
echo "[+] Gerando dados próprios da VM2..."

# Dados de backup "corporativos"
cat > $VM2_DATA/corporate-backup.sql << 'EOF'
-- BACKUP CORPORATIVO - DADOS SENSÍVEIS
-- VM2 Backup Server

CREATE TABLE corporate_financial_data (
    id SERIAL PRIMARY KEY,
    account_number VARCHAR(30),
    account_holder VARCHAR(100),
    balance DECIMAL(15,2),
    transaction_history TEXT,
    tax_id VARCHAR(20)
);

INSERT INTO corporate_financial_data VALUES
(1, '001-98765-1', 'João Silva', 150000.00, 'Large transactions: 50000, 75000', '123.456.789-00'),
(2, '001-54321-2', 'Maria Santos', 89000.50, 'Monthly salary deposits', '987.654.321-00'),
(3, '001-12345-3', 'Empresa XYZ Ltda', 2500000.00, 'Contract payments, investments', '12.345.678/0001-90');

CREATE TABLE employee_records (
    id SERIAL PRIMARY KEY,
    employee_id VARCHAR(20),
    full_name VARCHAR(100),
    position VARCHAR(50),
    salary DECIMAL(10,2),
    bonus DECIMAL(10,2),
    performance_rating INTEGER,
    personal_notes TEXT
);

INSERT INTO employee_records VALUES
(1, 'EMP-2024-001', 'Carlos Oliveira', 'CTO', 25000.00, 5000.00, 9, 'Key technical leader - access to all systems'),
(2, 'EMP-2024-002', 'Ana Costa', 'CFO', 22000.00, 8000.00, 8, 'Financial oversight - sensitive data access'),
(3, 'EMP-2024-003', 'Pedro Santos', 'Security Lead', 18000.00, 3000.00, 10, 'Security infrastructure - high clearance');
EOF

# Logs de backup corporativo
cat > $VM2_DATA/backup-logs.json << 'EOF'
{
  "backup_jobs": [
    {
      "job_id": "BK-2024-001",
      "type": "full_database",
      "source": "production-db-01",
      "destination": "vm2-backup-storage",
      "size_gb": 45.7,
      "status": "completed",
      "encryption_key": "corp_bk_key_2024_secure",
      "timestamp": "2024-12-19T02:00:00Z"
    },
    {
      "job_id": "BK-2024-002",
      "type": "file_system",
      "source": "nas-storage-01",
      "destination": "vm2-backup-storage",
      "size_gb": 123.4,
      "status": "completed",
      "encryption_key": "nas_bk_2024_key",
      "timestamp": "2024-12-19T04:30:00Z"
    }
  ],
  "credentials": {
    "vm2": "backup_master",
    "backup_password": "CorpBackup2024!Secure",
    "api_endpoint": "https://backup-api.corporacao.com/v1",
    "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
  }
}
EOF

# Scripts de automação com credenciais
cat > $SCRIPTS_DIR/cloud-backup.sh << 'EOF'
#!/bin/bash
# CLOUD BACKUP SCRIPT - CONFIDENCIAL

# AWS Credentials
export AWS_ACCESS_KEY_ID="AKIAI44QH8DHBEXAMPLE"
export AWS_SECRET_ACCESS_KEY="je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

# Google Cloud Credentials
export GOOGLE_APPLICATION_CREDENTIALS="/backup-storage/keys/gcp-service-account.json"
export GCP_PROJECT_ID="corporate-production-123456"
export GCP_BUCKET="corp-backups-2024"

# Azure Credentials
export AZURE_STORAGE_ACCOUNT="corpbackupstorage"
export AZURE_STORAGE_KEY="Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

# Database Credentials
export PROD_DB_HOST="prod-db-cluster.corporacao.com"
export PROD_DB_USER="backup_service"
export PROD_DB_PASSWORD="ProdDBBackup2024!Secure"
export PROD_DB_NAME="corporate_production"

# Encryption Keys
export BACKUP_ENCRYPTION_KEY="c0rpB4ckup3ncryptK3y2024!"
export SSL_CERT_PASSWORD="SSLPass2024!Secure"

echo "Iniciando backup cloud..."
# Comandos de backup aqui...
echo "Backup cloud concluído."
EOF

chmod +x $SCRIPTS_DIR/cloud-backup.sh

# Arquivo de chaves e certificados
cat > $VM2_DATA/security-keys.md << 'EOF'
# GERENCIAMENTO DE CHAVES - CONFIDENCIAL

## SSH Root Keys
- Password: vm2
- SSH Key: PLACEHOLDER

## Chaves de Criptografia:
- Backup Master Key: m4st3rB4ckupK3y2024!
- Database Encryption: db3ncryptK3y2024!
- File System Encryption: fs3ncryptK3y2024!

## Certificados SSL:
- Domain: *.corporacao.com
- Expiration: 2025-12-18
- Password: CorpSSL2024!Secure

## API Tokens:
- Monitoring: token_abc123def456
- Logging: token_ghi789jkl012
- Analytics: token_mno345pqr678
EOF

# 3. Configurar rsync daemon para servir os backups
cat > /etc/rsyncd.conf << 'EOF'
# Rsync Server Configuration - VM2 Backup Server
uid = nobody
gid = nogroup
use chroot = yes
max connections = 10
pid file = /var/run/rsyncd.pid
log file = /var/log/rsyncd.log
timeout = 300

[vm1-backups]
path = /backup-storage/vm1-backups
comment = VM1 System and Application Backups
read only = no
auth users = vm2
secrets file = /etc/rsyncd.secrets
hosts allow = 127.0.0.1,192.168.100.0/24

[vm2-data]
path = /backup-storage/vm2-data
comment = VM2 Corporate Backup Data
read only = no
auth users = vm2
secrets file = /etc/rsyncd.secrets
hosts allow = 127.0.0.1,192.168.100.0/24

[scripts]
path = /backup-storage/scripts
comment = Backup Scripts and Automation
read only = no
auth users = vm2
secrets file = /etc/rsyncd.secrets
hosts allow = 127.0.0.1,192.168.100.0/24

[logs]
path = /backup-storage/logs
comment = Backup Logs and Audit
read only = yes
auth users = vm2
secrets file = /etc/rsyncd.secrets
hosts allow = 127.0.0.1,192.168.100.0/24
EOF

# Criar arquivo de secrets
echo "vm2:vm2" > /etc/rsyncd.secrets

# 4. Configurar SSH
mkdir -p /root/.ssh
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# 5. Configurar agendamento de backups (cron)
crontab -l > /tmp/cron-backup 2>/dev/null || true
cat >> /tmp/cron-backup << 'EOF'
# Backup automático da VM1 - executa a cada 6 horas
0 */6 * * * /backup-storage/scripts/backup-vm1.sh

# Limpeza de logs antigos - diariamente às 2AM
0 2 * * * find /backup-storage/logs -name "*.log" -mtime +30 -delete

# Verificação de integridade - aos domingos às 3AM
0 3 * * 0 /backup-storage/scripts/verify-backups.sh
EOF

crontab /tmp/cron-backup

# 7. Configurar permissões
chmod -R 755 $BACKUP_BASE
chmod 600 /etc/rsyncd.secrets

# Iniciar rsync manualmente
/usr/bin/rsync --daemon --config=/etc/rsyncd.conf

# 8. Criar arquivo de documentação
cat > $BACKUP_BASE/README.txt << 'EOF'
=== SERVIDOR DE BACKUP VM2 - CORPORAÇÃO ===

ESTRUTURA:
/backup-storage/
├── vm1-backups/          # Backups da VM1
│   ├── system-backup/    # /opt/.system-backup-2025
│   ├── app-source/       # /home/vm1/Downloads/Projeto
│   ├── database/         # Backup do PostgreSQL
├── vm2-data/             # Dados próprios da VM2
├── scripts/              # Scripts de automação
└── logs/                 # Logs de backup

ACESSO RSYNC:
usuário: vm2
senha: vm2

MÓDULOS DISPONÍVEIS:
- vm1-backups    # Backups completos da VM1
- vm2-data       # Dados corporativos da VM2
- scripts        # Scripts com credenciais
- logs           # Logs de auditoria

EXEMPLO DE USO:
rsync -av rsync://vm2@192.168.100.4/vm1-backups/ ./backup/

EOF

echo "[+] Configuração da VM2 concluída!"
echo "[+] IP: 192.168.100.4"
echo "[+] Rsync: porta 873"
echo "[+] SSH: porta 22"
echo ""
echo "Estrutura criada:"
echo "✓ Backups simulados da VM1"
echo "✓ Dados corporativos da VM2"
echo "✓ Scripts com credenciais"
echo "✓ Rsync daemon configurado"
echo "✓ Agendamento de backups"
