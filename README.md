# nubulus-go

Cliente en Go de las APIs de Nubulus Network, compartido por los servicios que llaman a la
plataforma en nombre de alguien. El primero es `mcp-server`.

| Paquete | Qué hay |
|---|---|
| `nubulus` (raíz) | Cliente de DNS, túneles y accounts; errores tipados (`APIError`, `StatusOf`, `CodeOf`, `Explain`); validación de nombres como la de las APIs |
| `auth` | Validación de JWT de plataforma emitidos por Zitadel: RS256 contra el JWKS, issuer exacto, proyecto entre los `aud`, `exp` obligatorio y roles del proyecto |

Nace de `terraform-provider-nubuluscloud/internal/nubulus` (commit `d0a266d`), y el provider lo usa
en lugar de su copia.

## Uso

```go
// Con el token de un usuario (lo que hace el MCP):
c, err := nubulus.New(ctx, nubulus.Config{
    TokenSource:   oauth2.StaticTokenSource(&oauth2.Token{AccessToken: userToken}),
    BaseTransport: sharedTransport, // compartido entre clientes, para reutilizar conexiones
    UserAgent:     "nubulus-mcp/1.0",
})
zones, err := c.DNS.ListZones(ctx)

// Con un token de aplicación de accounts-api (lo que hace Terraform):
c, err := nubulus.New(ctx, nubulus.Config{ClientID: id, ClientSecret: secret})
```

Los endpoints tienen valores por defecto de producción y se cambian en `Config`.

## Instalación

```sh
go get github.com/nubulus-network/nubulus-go@latest
```

## Versiones

SemVer con tags `vX.Y.Z`. Mientras sea `v0`, puede haber cambios incompatibles entre versiones
menores.

## Licencia

MPL-2.0, como `terraform-provider-nubuluscloud`, del que procede el código.
