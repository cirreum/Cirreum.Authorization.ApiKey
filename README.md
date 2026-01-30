# Cirreum Authorization Provider - API Key

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Authorization.ApiKey.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authorization.ApiKey/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Authorization.ApiKey.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authorization.ApiKey/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Authorization.ApiKey?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Authorization.ApiKey/releases)
[![License](https://img.shields.io/github/license/cirreum/Cirreum.Authorization.ApiKey?style=flat-square&labelColor=1F1F1F&color=F2F2F2)](https://github.com/cirreum/Cirreum.Authorization.ApiKey/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**API key authentication provider for the Cirreum Framework**

## Overview

**Cirreum.Authorization.ApiKey** provides header-based API key authentication for ASP.NET Core applications within the Cirreum ecosystem. It enables secure service-to-service communication and broker authentication scenarios where OAuth/OIDC flows are not appropriate.

### Key Features

- **Header-based authentication** - Validates API keys from configurable HTTP headers
- **Multi-client support** - Multiple clients can share the same header with unique keys
- **Secure validation** - Constant-time comparison prevents timing attacks
- **Role-based authorization** - Configure roles per client for fine-grained access control
- **Seamless integration** - Works alongside audience-based providers (Entra, Okta) in the same application

#### Dynamic API Key Resolution (NEW)

For scenarios with hundreds of partners/customers, use database-backed dynamic resolution:

- **Efficient database lookup** - Use `X-Client-Id` header to query only relevant keys
- **Built-in caching** - Configurable TTL to reduce database load
- **Composite resolvers** - Chain config-based and database-backed resolvers
- **Extensible base class** - Implement `DynamicApiKeyClientResolver` for custom storage

### Use Cases

- Service-to-service communication
- Broker applications pushing data to APIs
- External system integrations
- Background job authentication
- IoT device connectivity

## Installation
```bash
dotnet add package Cirreum.Authorization.ApiKey
```

## Configuration

Add API key clients to your `appsettings.json`:
```json
{
  "Cirreum": {
    "Authorization": {
      "Providers": {
        "ApiKey": {
          "Instances": {
            "TrackBroker": {
              "Enabled": true,
              "HeaderName": "X-Api-Key",
              "ClientId": "track-broker",
              "ClientName": "Track Broker Application",
              "Key": "your-secure-api-key-here",
              "Roles": ["App.System"]
            },
            "ExternalService": {
              "Enabled": true,
              "HeaderName": "X-Api-Key",
              "ClientId": "external-service",
              "ClientName": "External Integration Service",
              "Key": "different-secure-key",
              "Roles": ["App.Agent"]
            }
          }
        }
      }
    }
  }
}
```

### Configuration Properties

| Property | Required | Description |
|----------|----------|-------------|
| `Enabled` | Yes | Whether this client is active |
| `HeaderName` | Yes | HTTP header name to check (default: `X-Api-Key`) |
| `ClientId` | Yes | Unique identifier for the client, used in claims |
| `ClientName` | No | Display name for the client (defaults to ClientId) |
| `Key` | No* | The API key value (*or provide via `ConnectionStrings:{InstanceName}`) |
| `Roles` | No | Roles to assign to authenticated requests |

### Secure Key Storage

API keys can be provided in two ways (checked in order):

1. **Direct value** - `Key` property in instance configuration (dev/testing only)
2. **Connection string** - `ConnectionStrings:{InstanceName}` in configuration (production)

For production environments, store API keys in Azure Key Vault using the connection string pattern:
```json
{
  "ConnectionStrings": {
    "LapCastBroker": "@Microsoft.KeyVault(SecretUri=https://your-vault.vault.azure.net/secrets/LapCastBrokerKey)"
  },
  "Cirreum": {
    "Authorization": {
      "Providers": {
        "ApiKey": {
          "Instances": {
            "LapCastBroker": {
              "Enabled": true,
              "HeaderName": "X-Api-Key",
              "ClientId": "lapcast-broker",
              "ClientName": "LapCast Broker",
              "Roles": ["App.System"]
            }
          }
        }
      }
    }
  }
}
```

The instance name (`LapCastBroker`) is used as the connection string key, allowing both the API and client applications to resolve the same secret from Key Vault using `configuration.GetConnectionString("LapCastBroker")`.

For local development, use user secrets or direct configuration:
```json
{
  "Cirreum": {
    "Authorization": {
      "Providers": {
        "ApiKey": {
          "Instances": {
            "LapCastBroker": {
              "Enabled": true,
              "HeaderName": "X-Api-Key",
              "ClientId": "lapcast-broker",
              "Key": "dev-only-key"
            }
          }
        }
      }
    }
  }
}
```

### Generating API Keys

For secure key generation, use `RandomNumberGenerator`:
```csharp
var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
```

## Architecture

The provider follows the Cirreum header-based authorization pattern:
```text
ApiKeyAuthorizationRegistrar
└── Extends HeaderAuthorizationProviderRegistrar
    ├── Registers clients in ApiKeyClientRegistry
    ├── Registers scheme via AuthorizationSchemeRegistry.RegisterHeaderScheme()
    └── Configures ApiKeyAuthenticationHandler

ApiKeyAuthenticationHandler
├── Extracts key from configured header
├── Validates against ApiKeyClientRegistry
├── Builds ClaimsPrincipal with ClientId, ClientName, Roles
└── Uses constant-time comparison for security

ApiKeyAuthorizationInstanceSettings
└── Extends HeaderAuthorizationProviderInstanceSettings
    └── HeaderName, ClientId, ClientName, Roles
```

### Authentication Flow

1. Request arrives with API key header (e.g., `X-Api-Key: your-key`)
2. `ForwardDefaultSelector` detects header and routes to API key scheme
3. `ApiKeyAuthenticationHandler` extracts the key value
4. `ApiKeyClientRegistry.ValidateKey()` performs secure comparison against all registered clients for that header
5. On match, handler builds `ClaimsPrincipal` with client identity and roles
6. Authorization policies evaluate roles as normal

### Multi-Client Support

Multiple clients can use the same header name with different keys:
```json
{
  "ApiKey": {
    "Instances": {
      "ClientA": {
        "HeaderName": "X-Api-Key",
        "ClientId": "client-a",
        "Key": "key-for-client-a",
        "Roles": ["App.Admin"]
      },
      "ClientB": {
        "HeaderName": "X-Api-Key",
        "ClientId": "client-b",
        "Key": "key-for-client-b",
        "Roles": ["App.User"]
      }
    }
  }
}
```

The `ApiKeyClientRegistry` validates the provided key against all clients registered for that header and returns the matching client, enabling different roles and identities per key.

## Dynamic API Key Resolution

For large-scale deployments with many partners/customers, implement database-backed resolution:

### Basic Setup

```csharp
builder.AddAuthorization(auth => auth
    .AddDynamicApiKeys<DatabaseApiKeyResolver>(
        headers: ["X-Api-Key"],
        options => options.WithCaching())
);
```

### Implementing a Custom Resolver

```csharp
public class DatabaseApiKeyResolver : DynamicApiKeyClientResolver {
    private readonly IDbConnection _db;

    public DatabaseApiKeyResolver(
        IApiKeyValidator validator,
        IOptions<ApiKeyValidationOptions> options,
        IDbConnection db,
        ILogger<DatabaseApiKeyResolver> logger)
        : base(validator, options, logger) {
        _db = db;
    }

    public override IReadOnlySet<string> SupportedHeaders =>
        new HashSet<string> { "X-Api-Key" };

    protected override async Task<IEnumerable<StoredApiKey>> LookupKeysAsync(
        string headerName,
        ApiKeyLookupContext context,
        CancellationToken cancellationToken) {

        // Use X-Client-Id header for efficient database lookup
        var clientId = context.GetHeader("X-Client-Id");
        if (!string.IsNullOrEmpty(clientId)) {
            return await _db.QueryAsync<StoredApiKey>(
                "SELECT * FROM ApiKeys WHERE ClientId = @ClientId AND IsActive = 1",
                new { ClientId = clientId });
        }

        // Fallback: return all keys for the header (less efficient)
        return await _db.QueryAsync<StoredApiKey>(
            "SELECT * FROM ApiKeys WHERE HeaderName = @HeaderName AND IsActive = 1",
            new { HeaderName = headerName });
    }
}
```

### With Caching

```csharp
builder.AddAuthorization(auth => auth
    .AddDynamicApiKeys<DatabaseApiKeyResolver>(
        headers: ["X-Api-Key"],
        options => options.WithCaching(caching => {
            caching.DefaultExpiration = TimeSpan.FromMinutes(5);
            caching.SlidingExpiration = TimeSpan.FromMinutes(1);
        }))
);
```

### Composite Resolution (Config + Database)

Static keys from appsettings are automatically checked first, then the dynamic resolver:

```csharp
// Config keys (appsettings.json) + Database keys - automatic composite
builder.AddAuthorization(auth => auth
    .AddDynamicApiKeys<DatabaseApiKeyResolver>(
        headers: ["X-Api-Key"],
        options => options.WithCaching())
);
```

## Security Considerations

- **Constant-time comparison** - Key validation uses `CryptographicOperations.FixedTimeEquals` to prevent timing attacks
- **Key storage** - Never commit API keys to source control; use Azure Key Vault or similar secret management
- **Key rotation** - Plan for key rotation by supporting multiple active keys during transition periods
- **Transport security** - Always use HTTPS to protect keys in transit
- **Least privilege** - Assign minimum required roles to each client

## Claims

Authenticated requests receive the following claims:

| Claim | Value |
|-------|-------|
| `ClaimTypes.NameIdentifier` | ClientId |
| `ClaimTypes.Name` | ClientName |
| `ClaimTypes.Role` | Each configured role |
| `client_type` | `api_key` |
| `auth_scheme` | The scheme name |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Cirreum Foundation Framework**  
*Layered simplicity for modern .NET*