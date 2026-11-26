# Seguridad en Runtime con eBPF y Tetragon en Kubernetes

Documentación y laboratorio práctico sobre observabilidad profunda y *enforcement* síncrono en el kernel de Linux utilizando **eBPF** y **Cilium Tetragon**.

## 1. ¿Por qué eBPF y Tetragon frente a agentes tradicionales?

Los agentes de seguridad tradicionales operan en *user-space* (leyendo logs de `auditd` o usando `ptrace`), lo que introduce dos limitaciones críticas a escala:

*   **Ventana de ataque (TOCTOU):** Entre que el agente detecta una *syscall* maliciosa en *user-space* y decide detener el proceso, el atacante dispone de milisegundos suficientes para exfiltrar secretos o abrir una *reverse shell*.
*   **Costo y rendimiento (FinOps):** Copiar millones de eventos desde el kernel hacia *user-space* incrementa el consumo de CPU/RAM en todos los nodos (`DaemonSet`) y dispara los costos de ingesta del SIEM (cobro por GB/día).

**Tetragon** resuelve esto ejecutando programas eBPF verificados directamente en el kernel:
*   **Filtrado *in-kernel*:** Descarta el ruido antes de enviarlo a *user-space*.
*   **Enforcement síncrono:** Permite enviar `Sigkill` antes de que la *syscall* retorne.
*   **Declarativo en Kubernetes:** Se gestiona mediante CRDs (`TracingPolicy` y `TracingPolicyNamespaced`) sin modificar el código de las aplicaciones ni inyectar *sidecars*.

### Trade-off: FinOps vs. Visibilidad Forense
Filtrar agresivamente en el kernel reduce costos de cómputo y SIEM, pero puede generar **puntos ciegos forenses** (falsos negativos). La estrategia recomendada es la **telemetría por capas**:
*   **SIEM (Alto costo):** Solo eventos de alta fidelidad (shells inesperadas, lectura de `/etc/shadow`, escalada de privilegios).
*   **Métricas (Bajo costo - Prometheus):** Contadores agregados de eventos bloqueados o anómalos.
*   **Alcance por criticidad:** Reglas estrictas en *namespaces* críticos (ej. pagos, autenticación).

---

## 2. Estrategia de Adopción (Zero Trust Pragmático)

Activar `Sigkill` desde el día 1 en producción conlleva un riesgo alto de disponibilidad (falsos positivos en *healthchecks* o *initContainers* que provoquen `CrashLoopBackOff`). El despliegue debe ser progresivo:

1.  **Fase 1 - Monitoring (Staging -> Producción):** Desplegar políticas sin `matchActions` para construir un *baseline* real de los procesos legítimos.
2.  **Fase 2 - Remediación colaborativa:** Corregir malas prácticas junto con desarrollo (ej. migrar *livenessProbes* con `curl` a `httpGet` nativo) o acotar excepciones estrictas mediante `podSelector`.
3.  **Fase 3 - Enforcement gradual:** Activar `Sigkill` progresivamente empezando por cargas críticas.

---

## 3. Laboratorio Local: Kind en Docker Desktop + WSL2

### Troubleshooting: Error `readlink /procRoot/self: no such file or directory`

Al seguir la documentación oficial de Tetragon para Kind en Linux nativo, se monta `/proc` del host en `/procHost` y se pasa `--set tetragon.hostProcPath=/procHost`.

En **Docker Desktop + WSL2**, esto falla al arrancar el pod de Tetragon:
```text
failed to create pid file '/var/run/tetragon/tetragon.pid' ... readlink /procRoot/self: no such file or directory
```

*   **Causa raíz:** En Linux, `/proc/self` resuelve dinámicamente el PID del proceso consultante dentro del *PID namespace* de ese `procfs`. En Docker Desktop + WSL2, el daemon corre en una capa aislada con un *PID namespace* distinto al del nodo de Kind; al consultar `/procHost/self`, el proceso de Tetragon no tiene un PID mapeado ahí y el kernel devuelve `ENOENT`.
*   **Solución en lab local (WSL2):** Omitir `--set tetragon.hostProcPath=/procHost` en Helm para que Tetragon utilice el `/proc` por defecto del propio contenedor de Kind (que comparte *PID namespace* con el pod mediante `hostPID: true`).
*   **Nota sobre producción (AKS / EKS):** Este problema no ocurre en clústeres productivos porque cada nodo es una máquina virtual real con su propio kernel y *root PID namespace*, donde `/proc` coincide 1 a 1 con los procesos del kernel.

### Instalación en Kind (WSL2)

```bash
helm repo add cilium [https://helm.cilium.io](https://helm.cilium.io)
helm repo update
helm install tetragon cilium/tetragon -n kube-system
```

---

## 4. Diseño de Políticas (`TracingPolicyNamespaced`)

Buenas prácticas aplicadas en el diseño:
*   Uso de `TracingPolicyNamespaced` + `podSelector` (`matchLabels`) para aplicar el principio de mínimo privilegio.
*   Separación de controles en políticas independientes (permite pasar a *enforcement* una regla de bajo riesgo como `/etc/shadow` sin acoplarla a reglas de binarios).
*   Uso de hooks LSM internos (`security_bprm_check` y `security_file_open` con `syscall: false`) en lugar de *syscalls* crudas (`sys_openat`) para evitar evasiones por rutas relativas.
*   Lista explícita de shells (`/sh`, `/bash`, `/dash`, `/ash`, `/zsh`) en lugar de patrones amplios como `"sh"` que generan falsos positivos (`ssh`, scripts `.sh`).

### Política 1: Monitoreo / Bloqueo de binarios prohibidos

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: policy-payments-binary-program
  namespace: prod-payments
spec:
  podSelector:
    matchLabels:
      app: payments-api
  kprobes:
    - call: "security_bprm_check"
      syscall: false
      args:
        - index: 0
          type: "linux_binprm"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Postfix"
              values:
                - "/curl"
                - "/wget"
                - "/sh"
                - "/bash"
                - "/dash"
                - "/ash"
                - "/zsh"
          # Para Fase 2 (Enforcement), descomentar matchActions:
          # matchActions:
          #   - action: Sigkill
```

### Política 2: Protección de archivos sensibles

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: policy-payments-file-open
  namespace: prod-payments
spec:
  podSelector:
    matchLabels:
      app: payments-api
  kprobes:
    - call: "security_file_open"
      syscall: false
      args:
        - index: 0
          type: "file"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Equal"
              values:
                - "/etc/shadow"
          # Para Fase 2 (Enforcement), descomentar matchActions:
          # matchActions:
          #   - action: Sigkill
```

---

## 5. Validación Empírica de `Sigkill`

*   **Prueba A (Proceso hijo vía `kubectl exec`):**
    *   *Modo Monitoring:* `kubectl exec -it httpd-pod -- sh` permite el acceso y registra el evento sin interrumpir el servicio.
    *   *Modo Enforcement (`Sigkill`):* El comando falla inmediatamente con `command terminated with exit code 137` ($128 + 9$, `SIGKILL`). El contenedor principal (`httpd`, PID 1) permanece en estado `Running` sin reinicios.
*   **Prueba B (Proceso raíz / PID 1):**
    *   Si una política con `Sigkill` coincide con el **PID 1** del contenedor (por ejemplo, un *entrypoint* basado en `/bin/sh`), el contenedor muere y entra en `CrashLoopBackOff` (bajo `restartPolicy: Always`).

---

## 6. Defensa en Profundidad (Más allá de listas negras)

Filtrar únicamente por nombre de binario (`Postfix: "/curl"`) puede evadirse renombrando el ejecutable (`cp /usr/bin/curl /tmp/mi-app && /tmp/mi-app`). Para cerrar este vector se combinan capas:

1.  **Shift Left (Imagen):** Utilizar imágenes **Distroless** o mínimas (*multi-stage builds*) para eliminar shells y utilidades (`cp`, `curl`, `wget`) desde el *build*.
2.  **Hardening del Pod (`SecurityContext`):** Configurar `readOnlyRootFilesystem: true` para impedir la escritura en el sistema de archivos raíz.
3.  **Control por comportamiento en Tetragon:** Para volúmenes que requieran escritura (ej. `emptyDir` en `/tmp`), bloquear cualquier ejecución originada desde esa ruta (`Prefix: "/tmp/"` en `security_bprm_check`).
4.  **Seguridad de Red (Egress L7 / FQDN):**
    *   Las `NetworkPolicy` nativas de Kubernetes solo operan en **L3/L4** (IPs/puertos), lo cual es ineficiente frente a APIs externas detrás de CDNs con IPs dinámicas. Abrir `0.0.0.0/0:443` rompe el modelo Zero Trust y habilita exfiltración por HTTPS.
    *   **Solución recomendada con eBPF:** Usar `CiliumNetworkPolicy` con `toFQDNs`, que intercepta consultas DNS e inyecta dinámicamente las IPs permitidas en los mapas eBPF del kernel sin la sobrecarga de *sidecars* de un Service Mesh tradicional (como Istio).

---

## 7. Referencias y Comandos Útiles

*   **Listar funciones disponibles del kernel para enganchar *kprobes*:**
    ```bash
    sudo cat /sys/kernel/tracing/available_filter_functions | grep fd_install
    ```
*   **Consultar firma y argumentos exactos de funciones del kernel:** [Elixir Bootlin](https://elixir.bootlin.com)
*   **Referencia oficial de API para `TracingPolicy`:** [Tetragon TracingPolicy Reference](https://tetragon.io/docs/reference/tracing-policy/)