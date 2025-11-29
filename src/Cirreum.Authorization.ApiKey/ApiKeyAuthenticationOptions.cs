namespace Cirreum.AuthorizationProvider.ApiKey;

using Microsoft.AspNetCore.Authentication;

/// <summary>
/// Options for the API key authentication handler.
/// </summary>
public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
{
	/// <summary>
	/// Gets or sets the HTTP header name where the API key is expected.
	/// </summary>
	public string HeaderName { get; set; } = "X-Api-Key";
}
