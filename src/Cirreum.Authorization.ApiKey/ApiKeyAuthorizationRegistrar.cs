namespace Cirreum.Authorization.ApiKey;

using Cirreum.Authorization.ApiKey.Configuration;
using Cirreum.AuthorizationProvider;
using Microsoft.AspNetCore.Authentication;

/// <summary>
/// Registrar for API key-based authorization provider instances.
/// </summary>
public class ApiKeyAuthorizationRegistrar
	: HeaderAuthorizationProviderRegistrar<ApiKeyAuthorizationSettings, ApiKeyAuthorizationInstanceSettings> {

	/// <inheritdoc/>
	public override string ProviderName => "ApiKey";

	/// <inheritdoc/>
	public override void ValidateSettings(ApiKeyAuthorizationInstanceSettings settings) {

		if (string.IsNullOrWhiteSpace(settings.ClientId)) {
			throw new InvalidOperationException(
				$"ApiKey provider instance '{settings.Scheme}' requires a ClientId.");
		}

		if (string.IsNullOrWhiteSpace(settings.HeaderName)) {
			throw new InvalidOperationException(
				$"ApiKey provider instance '{settings.Scheme}' requires a HeaderName.");
		}

	}

	/// <inheritdoc/>
	protected override void AddAuthenticationHandler(
		string schemeName,
		ApiKeyAuthorizationInstanceSettings settings,
		AuthenticationBuilder authBuilder) {
		authBuilder.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(
			schemeName,
			options => {
				options.HeaderName = settings.HeaderName;
			});
	}

}
