namespace Cirreum.AuthorizationProvider.ApiKey;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

/// <summary>
/// Authentication handler that validates API keys against registered clients
/// in the <see cref="ApiKeyClientRegistry"/>.
/// </summary>
public class ApiKeyAuthenticationHandler(
	IOptionsMonitor<ApiKeyAuthenticationOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder,
	ApiKeyClientRegistry clientRegistry
) : AuthenticationHandler<ApiKeyAuthenticationOptions>(
		options,
		logger,
		encoder) {

	/// <inheritdoc/>
	protected override Task<AuthenticateResult> HandleAuthenticateAsync() {

		if (!this.Request.Headers.TryGetValue(this.Options.HeaderName, out var apiKeyHeaderValues)) {
			return Task.FromResult(AuthenticateResult.NoResult());
		}

		var providedKey = apiKeyHeaderValues.FirstOrDefault();
		if (string.IsNullOrWhiteSpace(providedKey)) {
			return Task.FromResult(AuthenticateResult.NoResult());
		}

		var client = clientRegistry.ValidateKey(this.Options.HeaderName, providedKey);
		if (client is null) {
			if (this.Logger.IsEnabled(LogLevel.Warning)) {
				this.Logger.LogWarning(
					"API key validation failed for header {HeaderName} with provided key: {ProvidedKey}",
					this.Options.HeaderName,
					providedKey);
			}
			return Task.FromResult(AuthenticateResult.Fail("Invalid API key"));
		}

		var claims = new List<Claim>
		{
			new(ClaimTypes.NameIdentifier, client.ClientId),
			new(ClaimTypes.Name, client.ClientName),
			new("client_type", "api_key"),
			new("auth_scheme", client.Scheme)
		};

		foreach (var role in client.Roles) {
			claims.Add(new Claim(ClaimTypes.Role, role));
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
		return Task.FromResult(AuthenticateResult.Success(ticket));
	}
}
