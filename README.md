# 🛡️ Secure IDP Platform (`secure-idp-platform`)

Arquitectura de referencia de una **Plataforma Interna de Desarrollo (IDP) Segura** diseñada bajo principios de **Zero Trust**, **Defense in Depth** y **FinOps** para entornos Cloud-Native en producción.

Este repositorio documenta y automatiza controles de seguridad de extremo a extremo: desde la construcción inmutable de artefactos hasta la protección en tiempo de ejecución a nivel de kernel, evitando fricción innecesaria en el *Lead Time* de los equipos de desarrollo.

---


## 🚀 Módulos de la Plataforma

| Módulo | Enfoque Técnico | Estado | Documentación |
| :--- | :--- | :---: | :--- |
| **01. Supply Chain & Admisión Zero Trust** | SLSA, Cosign Keyless (OIDC/Fulcio/Rekor), Trivy SBOM (SPDX), Kyverno CEL (`policies.kyverno.io/v1`), Break-Glass | ✅ Implementado | [Ver detalle](./01-supply-chain-security/README.md) |
| **02. Runtime & Kernel Security (eBPF)** | Tetragon / Cilium `TracingPolicies`, bloqueo de exfiltración de credenciales en vivo | 🚧 Planificado | — |
| **03. AppSec Asíncrono a Escala** | Security Gates sin fricción, priorización por explotabilidad (EPSS/KEV) | 🚧 Planificado | — |
| **04. Workload Identity Zero Trust** | Eliminación de secretos estáticos con OIDC, SPIFFE/SPIRE y Pod Identity | 🚧 Planificado | — |
| **05. FinOps, CNAPP & Incident Response** | Aislamiento forense, detección de *Denial of Wallet* y validación IaC | 🚧 Planificado | — |

---

## 🎯 Principios de Diseño

1. **Cero llaves estáticas:** Todas las identidades de CI/CD y cargas de trabajo operan con tokens efímeros (OIDC) para eliminar costos operativos de rotación y minimizar el *blast radius*.
2. **Inmutabilidad por contenido:** Ningún artefacto se firma ni se despliega usando tags mutables (`:latest`, `:v1.4.2`); todo se referencia por `digest` (`@sha256:...`).
3. **Resiliencia operativa (*Break-Glass*):** La seguridad nunca debe forzar un apagado global de controles durante un incidente crítico; las excepciones son acotadas, auditadas y auto-expirables.