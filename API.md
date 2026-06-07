# 🔌 IOC Manager API Documentation

Esta API permite la integración programática para añadir, consultar y eliminar IOCs (Indicators of Compromise) desde sistemas externos como SIEMs, SOARs o scripts de automatización.

---

## 🔐 Autenticación

Todas las peticiones a la API requieren un **Token de Acceso**.
El token se puede enviar de tres formas (en orden de prioridad):

1.  **Header Authorization** (Recomendado): `Authorization: Bearer <TOKEN>`
2.  **Header X-API-Key**: `X-API-Key: <TOKEN>`
3.  **Query Parameter**: `?token=<TOKEN>`

### Gestión de Tokens
Los tokens se generan en el Panel de Administración (**Configuración > API Keys**).
Cada token tiene permisos asociados (Scopes):
*   `READ`: Solo lectura (consultar estado, resúmenes, listas).
*   `WRITE`: Escritura (bloquear, desbloquear IPs).

---

## 📡 Endpoints (Base URL: `/api`)

### 1. Estado del Servicio
Verifica si la API está operativa.

*   **GET** `/`
*   **Auth**: Token válido (Cualquier scope)
*   **Respuesta**:
    ```json
    {
      "service": "IOC Manager API",
      "status": "running",
      "endpoints": ["..."]
    }
    ```

---

### 2. Bloquear IP / Añadir IOC
Añade una o varias IPs a las listas de bloqueo. Soporta detección de duplicados, validación de CIDR, cálculo de TTL y notas.

*   **POST** `/bloquear-ip`
*   **Auth**: Scope `WRITE`
*   **Headers**:
    *   `Idempotency-Key` (Opcional): Cadena única para evitar duplicados en retries.
*   **Payload (JSON)**:
    Puede ser un objeto único o una lista en el campo `items`.

    ```json
    {
      "ip": "1.2.3.4",             // Requerido (o range, o cidr)
      "tags": ["Multicliente"],    // Requerido (Lista de tags)
      "ttl": "30d",                // Opcional (Def: permanente). Ej: 3600 (seg), "24h", "7d"
      "note": "Ataque SSH",        // Opcional
      "alert_id": "TICKET-1234",   // Opcional (ID de ticket externo)
      "force": false               // Opcional (True para sobrescribir datos existentes)
    }
    ```

    **Respuesta (200 OK / 207 Partial):**
    ```json
    {
      "status": "ok",      // "ok", "partial_ok", "error"
      "processed": [       // Lista de resultados por item
        {
          "count": 1,
          "ips": [{"ip": "1.2.3.4", "status": "ok", "expires_at": "..."}]
        }
      ],
      "errors": []
    }
    ```

---

### 3. Desbloquear IP / Eliminar IOC
Elimina una IP. Puede ser una eliminación global o solo retirar ciertos tags.

*   **DELETE** `/bloquear-ip`
*   **Auth**: Scope `WRITE`
*   **Payload (JSON)**:
    ```json
    {
      "ip": "1.2.3.4",
      "tags": ["Multicliente"]  // Opcional. Si se omite, BORRA la IP de todos los feeds.
    }
    ```
    *Si se envían `tags`, la IP solo se retira de esos tags específicos. Si se queda sin tags, se borra totalmente.*

*   **Respuesta**:
    ```json
    {
        "status": "deleted", // o "updated" si fue parcial
        "ip": "1.2.3.4",
        "scope": "global"    // o "partial"
    }
    ```

---

### 4. Consultar Estado de IP
Obtiene los detalles completos de una IP (tags, expiración, origen).

*   **GET** `/estado/<IP>`
*   **Auth**: Scope `READ`
*   **Respuesta**:
    ```json
    {
      "status": "ok",
      "data": {
        "tags": ["Cliente", "Malware"],
        "ttl": 2592000,
        "expires_at": "2025-01-30T12:00:00",
        "source": "api",
        "alert_ids": ["TICKET-123"]
      }
    }
    ```

---

### 5. Resumen de Métricas
Obtiene contadores en tiempo real (ideal para monitorización tipo Zabbix/Grafana).

*   **GET** `/summary`
*   **Auth**: Scope `READ`
*   **Respuesta**:
    ```json
    {
      "ok": true,
      "total_ips": 150,
      "tags": {
        "Multicliente": 100,
        "Cliente": 50
      },
      "sources": {
        "manual": 10,
        "api": 140
      },
      "timestamp": "2024-12-30T12:00:00Z"
    }
    ```

---

### 6. Historial de Métricas
Obtiene la serie temporal de métricas para gráficas.

*   **GET** `/counters/history?limit=30`
*   **Auth**: Scope `READ`
*   **Respuesta**: Array de objetos con snapshots diarios.

---

### 7. Descarga de Listas (Feeds)
Descarga directa de los ficheros de texto plano para integración en Firewalls.

*   **GET** `/lista/<TAG>`
    *   Retorna lista JSON detallada de IPs en ese tag.
*   **GET** `/feed/ioc-feed-bpe.txt`
    *   Retorna texto plano (una IP por línea) del feed Cliente.
