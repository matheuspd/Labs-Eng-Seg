# VulnShop - Relatório resumido de vulnerabilidades

**Versão curta e prática**: descreve falhas importantes, localizações, impacto e ações prioritárias de remediação.
**Uso**: ambiente de laboratório/educacional. **NÃO** exponha em produção.

## 1. Resumo
VulnShop é uma aplicação intencionalmente vulnerável (Flask + PostgreSQL) usada para ensino e testes de penetração. Testes confirmaram falhas críticas como SQL Injection, autenticação fraca, upload inseguro, IDOR e XSS - todas permitindo acesso, manipulação e exposição de dados.

## 2. Ambiente de referência
- App: VulnShop Dashboard
- Tech: Flask, psycopg2, PostgreSQL, Bootstrap
- URL de teste: `http://localhost:5000`
- Objetivo: laboratório para ensino/pen-testing

## 3. Vulnerabilidades principais (prioridade)
- **SQL Injection (CRÍTICA)** - queries construídas por string em `/login`, `/products`, APIs. Impacto: bypass, extração e modificação de dados.
  *Remediação:* usar queries parametrizadas (`cursor.execute(sql, params)`) ou ORM.

- **Broken Authentication / Session (CRÍTICA)** - `SECRET_KEY` fraca hardcoded, senhas em texto simples, endpoints que expõem segredos. Impacto: forjar cookies, sequestro de contas.  
  *Remediação:* gerar `SECRET_KEY` forte via variável de ambiente, `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_SAMESITE='Lax'`, hash de senhas (bcrypt).

- **Insecure File Upload (CRÍTICA)** - `/upload` aceita qualquer arquivo, salva com nome original. Impacto: webshells, RCE.
  *Remediação:* validar MIME/extensão/tamanho, renomear com `uuid4()`, armazenar fora do webroot, scanner antivírus.

- **IDOR (CRÍTICA)** - `/user/<id>`, `/order/<id>` permitem acesso sem checagem de autorização.
  *Remediação:* verificar propriedade/role antes de entregar recurso (403 quando não autorizado).

- **XSS (ALTA)** - campos que retornam conteúdo sem escape; uso de `innerHTML`.
  *Remediação:* escapar saída, evitar `innerHTML`, usar `escape`/`escapejs`/`tojson`, aplicar CSP.

- **CSRF (ALTA)** - APIs POST sem tokens CSRF; CORS permissivo (`origins="*"`, `supports_credentials=True`).
  *Remediação:* tokens CSRF (Flask-WTF), restringir CORS para domínios confiáveis.

- **Information disclosure (ALTA)** - `/api/system_info`, `/debug` revelam `DATABASE_URL`, `secret_key`, env vars.
  *Remediação:* remover/proteger endpoints de debug; não logar segredos.

## 4. Recomendações imediatas
1. Retirar a app da internet.
2. Remover endpoints que expõem segredos (`/api/system_info`, `/debug`).
3. Setar `SECRET_KEY` via variável de ambiente e ativar cookies seguros.
4. Parametrizar todas as queries críticas (login, APIs).
5. Implementar CSRF e restringir CORS.
6. Validar uploads e armazenar com segurança.
7. Implementar checks de autorização por recurso.
8. Escapar saída e aplicar CSP.
9. Hash das senhas (bcrypt/argon2) e rotacionar sessões.
10. Adicionar logging/auditoria para mudanças sensíveis.

## 5. Exemplos rápidos (snippet)
**Parâmetros (psycopg2)**
```py
cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
```

**Configurar secret key + cookies**
```py
app.secret_key = os.environ['SECRET_KEY']
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax'
)
```

**Gerar SECRET_KEY**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
export SECRET_KEY='...'
```

**Ativar CSRF**
```py
from flask_wtf import CSRFProtect
csrf = CSRFProtect(app)
```

## 6. Aviso legal
Ambiente intencionalmente inseguro para fins educacionais. Não use essas técnicas para atacar sistemas reais. Execute apenas em ambientes controlados e autorizados.
