package com.pointblue.console.auth;

import javax.net.ssl.SSLContext;

/**
 * One OpenID Connect client registration.
 *
 * @param issuer       the provider's issuer URL (trailing slashes are dropped)
 * @param clientId     this client's id at the provider
 * @param clientSecret the client secret, or null for a public client (PKCE alone)
 * @param scopes       requested scopes; null means {@code openid profile email}
 * @param groupsClaim  dotted path of the groups claim ({@code groups}, {@code realm_access.roles}); null means {@code groups}
 * @param redirectUri  this client's callback URL, as registered at the provider
 * @param tls          TLS context for talking to the provider, or null for the JDK's default trust
 */
public record OidcConfig(String issuer, String clientId, String clientSecret, String scopes,
                         String groupsClaim, String redirectUri, SSLContext tls) {

    public OidcConfig {
        issuer = required("issuer", issuer).replaceAll("/+$", "");
        clientId = required("clientId", clientId);
        redirectUri = required("redirectUri", redirectUri);
        clientSecret = clientSecret == null || clientSecret.isBlank() ? null : clientSecret;
        scopes = scopes == null || scopes.isBlank() ? "openid profile email" : scopes.trim();
        groupsClaim = groupsClaim == null || groupsClaim.isBlank() ? "groups" : groupsClaim.trim();
    }

    private static String required(String what, String v) {
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException("an OIDC client needs " + what);
        }
        return v.trim();
    }

    @Override
    public String toString() {
        // never print the secret
        return "OidcConfig[issuer=" + issuer + ", clientId=" + clientId + ", secret=" + (clientSecret == null ? "none" : "set")
                + ", scopes=" + scopes + ", groupsClaim=" + groupsClaim + ", redirectUri=" + redirectUri + "]";
    }
}
