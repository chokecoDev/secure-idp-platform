# Tutorial de firma y validación de imágenes con Cosign y Kyverno

Este proyecto muestra un flujo completo para construir, publicar, firmar y validar imágenes de contenedores:

1. GitHub Actions construye la imagen y la publica en GitHub Container Registry.
2. Cosign firma la imagen sin llave (`keyless`) usando la identidad de GitHub Actions.
3. La firma se registra en Rekor.
4. Kyverno verifica la firma y exige que las imágenes se referencien por digest antes de admitir Pods.

## Contenido del repositorio

| Archivo | Descripción |
| --- | --- |
| `Dockerfile` | Construye una imagen basada en `httpd`. |
| `.github/workflows/build-and-sign.yml` | Construye, publica y firma la imagen mediante Cosign. |
| `imageValidationPolicy.yml` | Política de Kyverno que exige firmas válidas e imágenes inmóviles por digest. |
| `pod-pass.yml` | Ejemplo de Pod que intenta usar la imagen publicada. |
| `pod-error.yml` | Ejemplo de Pod sin firma ni referencia por digest, destinado a ser rechazado. |

## Flujo de GitHub Actions

El workflow se ejecuta al hacer push a `main` y realiza dos trabajos:

- **build**: construye la imagen y la publica como
  `ghcr.io/chokecodev/tutorial-cosign:<sha-del-commit>`.
- **sign**: inicia sesión con `GITHUB_TOKEN`, instala Cosign y firma la imagen
  publicada por su digest:
  `ghcr.io/chokecodev/tutorial-cosign@sha256:<digest>`.

El `GITHUB_TOKEN` proporciona una credencial temporal de identidad OpenID. Por ello, el workflow
debe solicitar los permisos `id-token: write` y `packages: write`.

## Política de validación

La política `verify-cosign-signature` se aplica al namespace `production`.

Valida:

- Pods creados o actualizados.
- Contenedores normales, contenedores `init` y contenedores efímeros.
- Firmas producidas por un workflow de GitHub Actions de este repositorio.
- El issuer de OIDC `https://token.actions.githubusercontent.com`.
- La transparencia de la firma en Rekor.
- Una referencia de imagen con digest, mediante `@sha256:<64-caracteres-hexadecimales>`.

Ante una imagen inválida, firma ausente o referencia por tag, la política deniega el recurso.

> Importante: las referencias por tag son mutables. Aunque el contenido coincida hoy,
> puede apuntar a otro contenido en el futuro. Utilizar siempre `@sha256:<digest>`.

## Requisitos

- Un cluster de Kubernetes.
- Kyverno con soporte para políticas `NamespacedImageValidatingPolicy`.
- Permisos para crear namespaces y políticas.
- Acceso a GHCR, GitHub Actions y Rekor desde el cluster.
- Cosign instalado localmente si se desea verificar una imagen manualmente.

## Instalación

Crear el namespace:

```bash
kubectl create namespace production
```

Aplicar la política:

```bash
kubectl apply -f imageValidationPolicy.yml
```

Comprobar que la política se instaló:

```bash
kubectl get namespacedimagevalidatingpolicy -n production
```