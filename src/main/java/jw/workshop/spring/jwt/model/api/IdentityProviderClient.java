package jw.workshop.spring.jwt.model.api;

public interface IdentityProviderClient {

	/**
	 * Get JWT token form identity provider based on provided configuration.
	 * 
	 * @return
	 */
	String getAccessToken();

	/**
	 * Validate JWT token.
	 * Check:
	 * 	- Signature
	 * 	- Expiration date
	 * 	- Issuer
	 * 	- etc
	 * 
	 * @param token
	 * @return
	 */
	boolean validateToken(String token);

}
