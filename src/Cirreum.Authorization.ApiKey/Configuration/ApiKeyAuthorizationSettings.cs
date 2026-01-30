namespace Cirreum.Authorization.ApiKey.Configuration;

using Cirreum.AuthorizationProvider.Configuration;

/// <summary>
/// Configuration settings for the API key authorization provider,
/// containing a collection of API key client instances.
/// </summary>
public class ApiKeyAuthorizationSettings
	: AuthorizationProviderSettings<ApiKeyAuthorizationInstanceSettings>;
