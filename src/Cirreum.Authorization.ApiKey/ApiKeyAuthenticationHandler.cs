namespace Cirreum.AuthorizationProvider.ApiKey;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using System.Security.Claims;
using System.Text.Encodings.Web;

/// <summary>
/// Authentication handler that validates API keys using the registered
/// <see cref="IApiKeyClientResolver"/>.
/// </summary>
/// <remarks>
/// <para>
/// This handler supports both configuration-based key resolution (for static keys
/// stored in appsettings/KeyVault) and dynamic resolution (for keys stored in
/// databases or external services).
/// </para>
/// <para>
/// The resolver is injected via dependency injection, allowing applications to
/// use the default <see cref="ConfigurationApiKeyClientResolver"/> or provide
/// a custom implementation.
/// </para>
/// </remarks>
public class ApiKeyAuthenticationHandler(
	IOptionsMonitor<ApiKeyAuthenticationOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder,
	IApiKeyClientResolver clientResolver
) : AuthenticationHandler<ApiKeyAuthenticationOptions>(
		options,
		logger,
		encoder) {

	/// <inheritdoc/>
	protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {

		if (!this.Request.Headers.TryGetValue(this.Options.HeaderName, out var apiKeyHeaderValues)) {
			return AuthenticateResult.NoResult();
		}

		var providedKey = apiKeyHeaderValues.FirstOrDefault();
		if (string.IsNullOrWhiteSpace(providedKey)) {
			return AuthenticateResult.NoResult();
		}

		// Build lookup context with all request headers (except the key value itself for security)
		var context = this.BuildLookupContext(this.Options.HeaderName);

		var result = await clientResolver.ResolveAsync(
			providedKey,
			context,
			this.Context.RequestAborted);

		if (!result.IsSuccess || result.Client is null) {
			if (this.Logger.IsEnabled(LogLevel.Warning)) {
				this.Logger.LogWarning(
					"API key validation failed for header {HeaderName}: {Reason}",
					this.Options.HeaderName,
					result.FailureReason ?? "Unknown");
			}
			return AuthenticateResult.Fail(result.FailureReason ?? "Invalid API key");
		}

		var client = result.Client;
		var claims = new List<Claim>
		{
			new(ClaimTypes.NameIdentifier, client.ClientId),
			new(ClaimTypes.Name, client.ClientName),
			new("client_type", "api_key"),
			new("auth_scheme", client.Scheme)
		};

		// Add roles
		foreach (var role in client.Roles) {
			claims.Add(new Claim(ClaimTypes.Role, role));
		}

		// Add custom claims if present
		if (client.Claims is not null) {
			foreach (var (claimType, claimValue) in client.Claims) {
				claims.Add(new Claim(claimType, claimValue));
			}
		}

		var identity = new ClaimsIdentity(claims, this.Scheme.Name);
		var principal = new ClaimsPrincipal(identity);
		var ticket = new AuthenticationTicket(principal, this.Scheme.Name);

		if (this.Logger.IsEnabled(LogLevel.Debug)) {
			this.Logger.LogDebug(
				"API key authenticated for client {ClientId} ({ClientName}) via header {HeaderName}",
				client.ClientId,
				client.ClientName,
				this.Options.HeaderName);
		}

		return AuthenticateResult.Success(ticket);
	}

	/// <summary>
	/// Builds the lookup context from the current request headers.
	/// </summary>
	/// <param name="apiKeyHeaderName">The header name containing the API key (excluded from context).</param>
	/// <returns>A context containing relevant request headers.</returns>
	private ApiKeyLookupContext BuildLookupContext(string apiKeyHeaderName) {
		// Build a dictionary of headers, excluding the API key header itself
		// Use case-insensitive comparison for header names
		var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		foreach (var header in this.Request.Headers) {
			// Skip the API key header for security
			if (string.Equals(header.Key, apiKeyHeaderName, StringComparison.OrdinalIgnoreCase)) {
				continue;
			}

			// Take first value for simplicity
			var value = header.Value.FirstOrDefault();
			if (!string.IsNullOrEmpty(value)) {
				headers[header.Key] = value;
			}
		}

		return new ApiKeyLookupContext(apiKeyHeaderName, headers);
	}
}
