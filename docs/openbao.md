# OpenBao: развёртывание и интеграция

OpenBao — открытый форк HashiCorp Vault (MPL 2.0). Мы используем его как
основной бэкенд секретов в проде.

## Dev

В `docker-compose.dev.yml` OpenBao поднимается в **dev-режиме**:
- in-memory storage (данные теряются при рестарте);
- авто-unseal;
- фиксированный root token: `root-token-dev`;
- KV v2 автоматически смонтирован на `secret/`.

Ничего дополнительно настраивать не нужно. Проверка:

```bash
docker compose -f docker-compose.dev.yml exec openbao bao status
# → Sealed: false
```

Переключить приложение на OpenBao:

```bash
# в .env или docker-compose
SECRETS_BACKEND=openbao
OPENBAO_URL=http://openbao:8200
OPENBAO_TOKEN=root-token-dev
OPENBAO_MOUNT=secret
```

Записать первый секрет (пример для пароля домена):

```bash
docker compose -f docker-compose.dev.yml exec openbao \
    bao kv put secret/domains/example.local/domain_password value=s3cret
```

Проверить:

```bash
docker compose -f docker-compose.dev.yml exec openbao \
    bao kv get secret/domains/example.local/domain_password
```

## Прод: persistent mode + Raft

Для прода рекомендуется **Raft storage** — встроенный кластер с репликацией.

Минимальный `openbao.hcl`

```hcl
ui = true

storage "raft" {
  path = "/openbao/data"
  node_id = "openbao-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = false
  tls_cert_file = "/openbao/tls/tls.crt"
  tls_key_file  = "/openbao/tls/tls.key"
}

api_addr = "https://openbao-1.openbao.svc:8200"
cluster_addr = "https://openbao-1.openbao.svc:8201"
disable_mlock = false
```

Развертывание в k8s:

```yml
apiVersion: v1
kind: Service
metadata:
  name: openbao
spec:
  clusterIP: None
  selector:
    app: openbao
  ports:
    - {name: api,     port: 8200}
    - {name: cluster, port: 8201}
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: openbao
spec:
  serviceName: openbao
  replicas: 3
  selector:
    matchLabels: {app: openbao}
  template:
    metadata: {labels: {app: openbao}}
    spec:
      containers:
        - name: openbao
          image: openbao/openbao:latest
          args: ["server", "-config=/openbao/config/openbao.hcl"]
          ports:
            - {containerPort: 8200, name: api}
            - {containerPort: 8201, name: cluster}
          volumeMounts:
            - {name: data,   mountPath: /openbao/data}
            - {name: config, mountPath: /openbao/config}
            - {name: tls,    mountPath: /openbao/tls, readOnly: true}
          securityContext:
            capabilities:
              add: ["IPC_LOCK"]
  volumeClaimTemplates:
    - metadata: {name: data}
      spec:
        accessModes: [ReadWriteOnce]
        resources: {requests: {storage: 20Gi}}
```

### Инициализация (один раз)

```bash
# 1) init на первом pod'е
kubectl exec -it openbao-0 -- bao operator init \
    -key-shares=5 -key-threshold=3

# Вернёт 5 unseal-ключей и root token. СОХРАНИТЕ ИХ В НАДЁЖНОМ МЕСТЕ.

# 2) unseal на каждом pod'е (3 ключа из 5)
for i in 0 1 2; do
  kubectl exec -it openbao-$i -- bao operator unseal
done

# 3) включить KV v2
kubectl exec -it openbao-0 -- env BAO_TOKEN=<root> \
    bao secrets enable -path=secret -version=2 kv

# 4) создать policy для приложения
kubectl exec -it openbao-0 -- env BAO_TOKEN=<root> \
    bao policy write postinstall - <<EOF
path "secret/data/domains/*" {
  capabilities = ["read"]
}
path "secret/metadata/domains/*" {
  capabilities = ["read", "list"]
}
EOF

# 5) токен для приложения через AppRole
kubectl exec -it openbao-0 -- env BAO_TOKEN=<root> \
    bao auth enable approle
kubectl exec -it openbao-0 -- env BAO_TOKEN=<root> \
    bao write auth/approle/role/postinstall \
        token_ttl=1h token_max_ttl=4h \
        policies=postinstall
```

`role_id` и `secret_id` передаются приложению через переменные окружения.


### AppRole в Django

В `apps/secrets/backends/openbao.py` сейчас поддерживается только токен-аутентификация. Для AppRole (рекомендуется в проде) добавьте:

```python
def _authenticate_approle(self):
    import hvac
    resp = self._client.auth.approle.login(
        role_id=settings.OPENBAO_ROLE_ID,
        secret_id=settings.OPENBAO_SECRET_ID,
    )
    return resp["auth"]["client_token"]
```

И в `apps/secrets/backends/openbao.py` — обновить инициализацию: если заданы `OPENBAO_ROLE_ID` и `OPENBAO_SECRET_ID`, использовать `AppRole`; иначе — токен.

Срок жизни токена (1h) — сервер должен периодически обновлять его. Это делается либо через фоновый `celery-task` каждые 30 минут, либо через `client side` на каждый вызов. Пока не реализовано...


### Health-проверки

- `/sys/health` — статус (`sealed/unsealed`, `standby/active`).
- Метрики Prometheus: OpenBao экспортирует их на `/v1/sys/metrics?format=prometheus`.

Для k8s — readinessProbe:

```yml
readinessProbe:
  httpGet:
    path: /v1/sys/health?standbyok=true&perfstandbyok=true
    port: 8200
```