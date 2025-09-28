# VulnShop Dashboard - Aplicação Web Vulnerável

> Algumas funcionalidades não foram implementadas e outras foram deixadas para trás, considerando que esta aplicação é apenas voltada para análise simplificada de vulnerabilidades web.

> Parte 1 foi feita com docker, segunda parte será implementada em 2 VMs para realizar a alavancagem.

> **Aviso:** Esta aplicação foi construída *intencionalmente vulnerável* para fins educacionais e testes de segurança. **NÃO** execute em produção nem exponha publicamente.

## Autores

- Matheus Pereira Dias
- Fernando Cirilo Zanchetta

## Descrição
VulnShop é um painel de vendas (simulação de dashboard para e‑commerce) projetado para demonstrar falhas comuns em aplicações web: SQL Injection, Broken Authentication, IDOR, XSS, upload inseguro, CSRF, entre outras. Use-o como laboratório controlado para treinar análises e mitigação de vulnerabilidades.

## Tecnologias
- Backend: Flask (Python 3.11)
- DB: PostgreSQL (psycopg2, opcional SQLAlchemy)
- Frontend: HTML5, Bootstrap 5, JS
- Extras: Flask-CORS (configurada de forma insegura intencionalmente)
- Containerização: Docker / docker‑compose (opcional)

## Estrutura
```
vulnerable-sales-dashboard/
├── app/
│   ├── main.py
│   ├── models.py
│   ├── templates/
│   ├── Dockerfile
│   └── requirements.txt
├── postgres/
│   ├── init.sql
│   └── Dockerfile
└── docker-compose.yml
```

## Como rodar (rápido)

### Local
1. Criar DB e usuário (ex.: `vulndb` / `vulnuser` / `vulnpass`) e importar `postgres/init.sql`.
2. Exportar `DATABASE_URL`:
```bash
export DATABASE_URL="postgresql://vulnuser:vulnpass@localhost:5432/vulndb"
```
3. Instalar dependências e executar:
```bash
pip install -r requirements.txt
python3 main.py
```
Acesse: `http://localhost:5000`

### Docker
```bash
docker compose up --build -d
```

> Observação: o projeto roda em modo *debug* por padrão (intencional).

## Credenciais de teste (pré‑cadastradas)
- **admin / admin123** (admin)
- **employee1 / emp123** (employee)
- **employee2 / emp123** (employee)
- **customer1 / 123456** (customer)
- **customer2 / qwerty** (customer)

(Detalhes no `postgres/init.sql`)

## Principais vulnerabilidades implementadas (resumo)
- **SQL Injection (CRÍTICA):** Queries montadas com f-strings/concat - login, buscas e APIs vulneráveis.
- **Broken Authentication (CRÍTICA):** Senhas em texto plano; `app.secret_key` fraca/visível; sessões sem flags seguras.
- **Insecure File Upload (CRÍTICA):** Uploads sem validação; arquivos salvos com nome original.
- **IDOR (CRÍTICA):** `/user/<id>`, `/order/<id>` acessíveis sem checagem de autorização.
- **XSS (ALTA):** Campos que retornam HTML sem escape; uso de `innerHTML`.
- **CSRF (ALTA):** Endpoints POST sem tokens CSRF; CORS permissivo (`origins="*"` com credentials).
- **Information Disclosure (ALTA/MÉDIA):** Endpoints debug exibem `DATABASE_URL`, `secret_key`, variáveis de ambiente.
- **Command/File Read RCE (CRÍTICA/ALTA):** Endpoints para executar comandos/ler arquivos (intencionalmente perigosos).

## Endpoints e áreas sensíveis (para testes)
- `/login` - vulnerável a SQLi
- `/products` - busca suscetível a SQLi
- `/upload` - upload sem validação
- `/user/<id>` - IDOR (perfil de usuário)
- `/order/<id>` - IDOR (pedido)
- `/api/*` - APIs REST sem CSRF e com SQL concatenado
- `/debug`, `/api/system_info` - divulgam segredos (não use em produção)

## Sugestões de testes (checklist rápido)
- SQLi no login: `username = "admin'--"`
- Teste de IDOR: tente `/user/1`, `/order/1` com usuário sem privilégios
- XSS: inserir payloads em campos de descrição/comentários (ex.: `<script>alert(1)</script>`)
- Upload malicioso: envie webshells/arquivos perigosos e verifique acesso
- CSRF: criar página externa que faz POSTs contra APIs com `credentials: include`
- Testes automáticos: Burp Suite, sqlmap, OWASP ZAP

## Recomendações (uso seguro do laboratório)
- Rode em rede isolada (VM ou VLAN separada).
- Não use credenciais reais.
- Não exponha `DATABASE_URL` ou `SECRET_KEY`.
- Limite o tráfego externo (firewall) quando for executar exploits.
- Mantenha backups do DB de referência antes de testes destrutivos.

## Uso educacional e legal
Este repositório é para **treinamento autorizado**. Não utilize para atacar sistemas sem permissão. Respeite políticas locais e leis aplicáveis.
