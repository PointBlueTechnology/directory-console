package com.pointblue.console.auth;

import java.io.IOException;

/**
 * A sign-in the provider or this client refused: an error from the provider, an expired or unknown
 * state, a token that does not verify. The message is meant for the person signing in; transport
 * failures stay plain {@link IOException}s.
 */
public final class OidcException extends IOException {
    public OidcException(String message) {
        super(message);
    }
}
