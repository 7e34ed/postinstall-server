# Клиентские сертификаты (mTLS)

## Что это

Двухсторонний TLS: клиент предъявляет сертификат, reverse proxy его
проверяет и передаёт в Django подписанные заголовки. Django мапит
fingerprint сертификата на пользователя в БД.

## Схема

Browser ──[TLS + client cert]──> nginx ──[HTTP + X-SSL-Client-*]──> Django

Django **никогда** не парсит сертификат сам — только доверяет
заголовкам от доверенного proxy (IP из `AUTH_TRUSTED_PROXIES`).

## Настройка nginx

```nginx
server {
    listen 443 ssl;
    server_name postinstall.local;

    ssl_certificate     /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;

    # Проверка клиентского сертификата
    ssl_client_certificate /etc/nginx/ssl/ca.crt;    # CA, выпустивший клиентские
    ssl_verify_client      optional;                  # или required
    ssl_verify_depth       2;

    location / {
        proxy_pass http://django_upstream;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;

        # Передача клиентского сертификата
        proxy_set_header X-SSL-Client-Verify      $ssl_client_verify;
        proxy_set_header X-SSL-Client-Subject     $ssl_client_s_dn;
        proxy_set_header X-SSL-Client-Issuer      $ssl_client_i_dn;
        proxy_set_header X-SSL-Client-Fingerprint $ssl_client_fingerprint;
        proxy_set_header X-SSL-Client-Serial      $ssl_client_serial;
        proxy_set_header X-SSL-Client-NotBefore   $ssl_client_notbefore;
        proxy_set_header X-SSL-Client-NotAfter    $ssl_client_notafter;
    }
}
```

**Важно:**

- `ssl_verify_client optional` — сертификат можно не предъявлять (для смешанного входа).
- `ssl_verify_client required` — обязателен, тогда все пользователи заходят через mTLS.
- `ssl_client_certificate` — **CA, а не сам сертификат**. Nginx должен доверять УЦ.

```yml
tls:
  options:
    default:
      clientAuth:
        caFiles:
          - /certs/ca.crt
        clientAuthType: RequireAndVerifyClientCert
```

Traefik автоматически прокидывает `X-Forwarded-Tls-Client-Cert` (base64).
Этот формат требует отдельной обработки. Проще использовать nginx.

## Что нужно от заказчика

1. **Внутренний УЦ.** Обычно уже есть (или разворачивается за 1 день на базе `openssl ca` или `EJBCA`).
2. Клиентские сертификаты. Выпускаются на пользователей. Могут быть:
   - программные (файл **.p12** / **.pem**);
   - аппаратные (`Rutoken ECP` через **CryptoPro CSP** или **OpenSC**).
3. Корневой CA-сертификат кладётся в `/etc/nginx/ssl/ca.crt` на **reverse proxy**.
4. Доверенный IP proxy прописан в `AUTH_TRUSTED_PROXIES` на стороне **Django**.

## Порядок внедрения

1. Развернуть reverse proxy с `ssl_verify_client optional` (не `required`).
2. Настроить `AUTH_TRUSTED_PROXIES` в **Django** (IP proxy).
3. Включить `AUTH_MTLS_ENABLED=True` в **constance**.
4. Пользователи заходят, привязывают свои сертификаты через `/access/security/certificates/`.
5. Проверка: с сертификатом пользователь видит индикатор **AAL3** в **navbar**.
6. Когда все привязали — переключить `ssl_verify_client required` и
    `AUTH_MTLS_AUTO_LOGIN=True`. Вход по паролю отключится для всех,
    кроме аварийного **superuser**'а.

## Проверка сертификата вручную

```bash
# fingerprint
openssl x509 -in user.crt -noout -fingerprint -sha256
# SHA256 Fingerprint=AB:CD:...:EF

# subject
openssl x509 -in user.crt -noout -subject
# subject=CN=ivan,OU=users,O=company

# срок
openssl x509 -in user.crt -noout -dates
# notBefore=...
# notAfter=...
```

## Rutoken ECP

Если используется **Rutoken**:

- на клиенте ставится **CryptoPro CSP** (Windows) или **OpenSC** (Linux);
- сертификат с токена доступен браузеру через системный **certificate store**;
- при **mTLS-запросе** браузер предложит выбрать сертификат с токена;
- **PIN** **Rutoken**'а запрашивает сам **middleware**, до отправки в сеть.

Никаких специальных изменений в коде для Rutoken не требуется —
он работает как обычный клиентский сертификат. Отдельная интеграция
(**PKCS#11 API**) не нужна.

## Отладка

`cat /var/log/postinstall/server.log | grep mtls`

**Типичные проблемы:**

- `mtls: bad fingerprint from <ip>` — proxy не передал заголовки или передал битые.
- `mtls: unknown fingerprint` — пользователь не привязал сертификат в UI.
- `mtls: cert rejected (expired)` — истёк срок сертификата.
- `mtls: user X inactive` — пользователь отключён.

Если **AUTH_MTLS_ENABLED=True**, но middleware не срабатывает:

- проверить **AUTH_TRUSTED_PROXIES** (должен содержать **IP nginx**);
- проверить, что **nginx** действительно передаёт заголовки
    `(curl -v -k --cert user.crt --key user.key https://postinstall.local/).`
