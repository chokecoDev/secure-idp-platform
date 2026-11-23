# 🔐 Módulo 01: Seguridad en la Cadena de Suministro y Admisión Zero Trust

Este módulo implementa protección criptográfica de extremo a extremo para contenedores, desde su compilación en **GitHub Actions** hasta su admisión en **Kubernetes**, utilizando **Sigstore/Cosign (Keyless)**, **Trivy (SBOM SPDX)** y **Kyverno (`policies.kyverno.io/v1`)**.

---

## 🎯 Modelo de Amenazas: "El Tag Fantasma"

### Escenario de Ataque
Un atacante compromete las credenciales de un desarrollador con permisos de escritura en el registro privado (GHCR/ECR/ACR). Sin tocar el repositorio de Git ni pasar por CI/CD, compila una imagen troyanizada y ejecuta `docker push` sobrescribiendo un tag existente en producción (ej. `pagos-api:v1.4.2-prod`). Cuando Kubernetes escala horizontalmente (HPA) o reemplaza un Pod con `imagePullPolicy: Always`, descarga y ejecuta el código malicioso.

### Controles Implementados
1. **Firma *Keyless* vinculada a identidad OIDC:** Solo las imágenes construidas por el workflow autorizado en la rama `main` pueden obtener un certificado válido de firma.
2. **Inmutabilidad estricta por `digest`:** Tanto la firma/atestación en CI como el despliegue en Kubernetes exigen referencias `@sha256:...`, eliminando ataques de sobrescritura de tags y condiciones de carrera (*TOCTOU*).
3. **Admisión Zero Trust con Kyverno (`policies.kyverno.io/v1`):** Bloqueo determinístico en `CREATE` y `UPDATE` para `containers`, `initContainers` y `ephemeralContainers` (previniendo *bypass* vía `kubectl debug`).

---

## 🧠 Decisiones de Arquitectura (ADR)

### 1. ¿Por qué Cosign *Keyless* (OIDC) en lugar de llaves privadas en Secrets/KMS?
* **Seguridad (Zero Trust):** Las llaves privadas se generan en memoria del *runner* y se destruyen al finalizar el *job*. A diferencia de una llave estática (que solo prueba que *"alguien con el secreto firmó"*), OIDC vincula criptográficamente la firma a una **identidad verificable** (repositorio, workflow y rama exactos).
* **FinOps y Operaciones:** El costo real de KMS/Secrets Manager no es el almacenamiento mensual, sino las horas de ingeniería dedicadas a rotación periódica, distribución de llaves públicas a múltiples clústeres y la gestión de revocación masiva en caso de filtración.

### 2. ¿Cómo confía Kyverno en un certificado de Fulcio que expiró hace meses?
Los certificados emitidos por **Fulcio** tienen una vida útil de ~10 minutos. Para validar una imagen meses después, Kyverno se apoya en **Rekor** (log de transparencia *append-only* basado en un Árbol de Merkle):
1. Verifica que el certificado fue emitido por la raíz confiable de **Fulcio** y que la firma corresponde al `digest` de la imagen.
2. Verifica la prueba de inclusión y el **sello de tiempo criptográfico inmutable (*Signed Entry Timestamp* / SET)** registrado en **Rekor**.
3. Si el *timestamp* de Rekor cae dentro de la ventana de validez de 10 minutos del certificado, la firma es matemáticamente válida de forma permanente.

### 3. Separación de Deberes (*Separation of Duties*) en GitHub Actions
* Bloque global `permissions: {}` (denegación por defecto).
* El job `build` solo recibe `contents: read` y `packages: write`.
* El job `sign` corre en un *runner* aislado y es el único con `id-token: write`, evitando que código no confiable durante el `docker build` pueda solicitar tokens OIDC y firmar artefactos.
* Todas las GitHub Actions están fijadas (*pinned*) a su SHA de commit completo y el checkout deshabilita `persist-credentials: false`.
* **Orden atómico de evidencia:** El SBOM (`spdx-json`) se genera y atesta (`cosign attest --type spdxjson`) **antes** de firmar la imagen (`cosign sign`), evitando dejar imágenes firmadas huérfanas de SBOM si falla el escaneo.

---

## 🛡️ Política de Admisión en Kubernetes (`ImageValidatingPolicy`)

Se utiliza la API moderna basada en expresiones CEL **`policies.kyverno.io/v1`** (`ImageValidatingPolicy` a nivel de clúster) en lugar del recurso legado `ClusterPolicy` o políticas a nivel de namespace (`NamespacedImageValidatingPolicy`):

* **Aislamiento RBAC:** Al vivir a nivel de clúster, los operadores o pipelines con permisos dentro del namespace `production` no pueden editar ni eliminar la política para evadir el control.
* **Sin *drift* en GitOps:** En lugar de mutar tags a *digests* en vuelo (lo que genera *drift* constante en ArgoCD/Flux), la política rechaza directamente cualquier imagen que no esté fijada por `@sha256:[a-f0-9]{64}`.
* **Cobertura completa de contenedores:** Evalúa `containers`, `initContainers` y `ephemeralContainers`.

### Deuda Técnica / Endurecimiento Pendiente (Backlog del Módulo)
- [x] Reemplazar `matchConditions` por `namespaceSelector` en `matchConstraints` para filtrar en el API Server y reducir latencia/CPU en el webhook de Kyverno.
- [ ] Restringir `matchImageReferences` (evitar `glob: '*'`) para no bloquear *sidecars* legítimos inyectados (Istio, Datadog, Vault Agent) mientras se bloquean registros no autorizados.
- [ ] Acotar `subjectRegExp` a repositorios y *Reusable Workflows* específicos de producción.
- [ ] Agregar validación CEL de la atestación SBOM (`verifyAttestations`) además de la firma de imagen.

---

## 🚨 Runbook Operativo: Disponibilidad y *Break-Glass* (Emergencia)

**Escenario crítico:** Falla un servicio de pagos en producción ($50k USD/min de impacto) al mismo tiempo que GitHub Actions o los servicios públicos de Sigstore (Fulcio/Rekor) sufren una caída global.

### 1. Resiliencia ante caída de Sigstore (Verificación Offline)
Para no depender de llamadas en vivo a Rekor durante despliegues o escalados, la plataforma contempla el uso de **Sigstore Bundles** almacenados junto a la imagen en el registro privado (verificación *offline*) y, según análisis FinOps de criticidad, la evaluación de una instancia privada de Sigstore.

### 2. Mecanismo *Break-Glass* (Sin apagar la seguridad global)
**Nunca** se cambia la política global de `Deny` a `Audit` durante un incidente (evita ampliar el *blast radius* y el riesgo de olvidar reactivar el bloqueo). En su lugar se aplica una **`PolicyException`**:

1. **Alcance mínimo:** Exime únicamente a la política `verify-cosign-signature`, en el namespace `production`, para el *Deployment/Pod* y `digest` específicos del *hotfix*. El resto del clúster permanece en `Deny`.
2. **Aprobación y Auditoría:** Requiere aprobación de 2 personas (o rol RBAC de *Incident Commander*) y dispara una alerta de severidad crítica al SIEM/Slack.
3. **Auto-expiración (`CleanupPolicy`):** La `PolicyException` incluye un TTL automático (ej. 2–4 horas).

### 3. Comportamiento del Clúster al Expirar la Excepción
* **Pods en ejecución:** No se detienen ni se eliminan (el *Admission Controller* solo intercepta `CREATE` y `UPDATE`).
* **Escalado (HPA) / Reemplazo de nodos:** Al expirar la excepción, cualquier nuevo Pod con la imagen sin firmar será bloqueado por Kyverno.
* **Auditoría continua:** El *Background Scan* marca los Pods de emergencia como `Fail` en el `PolicyReport`, manteniendo visibilidad hasta que el *hotfix* vuelva a pasar por el pipeline estándar firmado.