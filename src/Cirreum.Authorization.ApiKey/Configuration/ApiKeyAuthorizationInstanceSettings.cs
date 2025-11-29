namespace Cirreum.AuthorizationProvider.ApiKey.Configuration;

using Cirreum.AuthorizationProvider.Configuration;

/// <summary>
/// Configuration settings for an individual API key authorization provider instance.
/// </summary>
/// <remarks>
/// Inherits <see cref="HeaderAuthorizationProviderInstanceSettings.HeaderName"/>,
/// <see cref="HeaderAuthorizationProviderInstanceSettings.ClientId"/>,
/// <see cref="HeaderAuthorizationProviderInstanceSettings.ClientName"/>, and
/// <see cref="HeaderAuthorizationProviderInstanceSettings.Roles"/> from the base class.
/// </remarks>
public class ApiKeyAuthorizationInstanceSettings : HeaderAuthorizationProviderInstanceSettings
{
	// All properties inherited from HeaderAuthorizationProviderInstanceSettings
	// Add any API key-specific properties here if needed in the future
}
