package jw.workshop.spring.jwt.infrastructure.keycloak;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import jw.workshop.spring.jwt.model.api.IdentityProviderClient;

/**
 * This service is used to retrieve and validate KeyCloak JWT access tokens.
 * 
 * To simplify things nimbus-jose-jwt library is used for JWT processing
 * 
 * @author jakub
 *
 */

@Service
public class KeyCloakClientService implements IdentityProviderClient {

	Logger logger = LoggerFactory.getLogger(KeyCloakClientService.class);


	@Autowired
	private KeyCloakConfiguration config;

	
	@Override
	public boolean validateToken(String token) {
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = loadJWTProcessor();
		
		SecurityContext ctx = null; 
		try {
			JWTClaimsSet claimsSet = jwtProcessor.process(token, ctx);
			return customClaimsValidator(claimsSet);
			
		} catch (ParseException | BadJOSEException | JOSEException e) {
			logger.error("Cannot parsing JWT token", e);
			return false;
		}
	}


	@Override
	public String getAccessToken() {
		String jwtToken = getKeycloakToken();
		KeycloakTokenResponse keycloakToken =  TokenUtils.tokenObjFromString(jwtToken);
		
		return keycloakToken.getAccessToken();
	}
	
	
	/**
	 * Implement here custom claims validation rules
	 * 
	 * @param claims
	 * @return
	 * @throws BadJWTException
	 */
	private boolean customClaimsValidator(JWTClaimsSet claims) throws BadJWTException {

        if (!claims.getIssuer().equalsIgnoreCase(loadJWTIssuer()) ){
            throw new BadJWTException("JWT issuer does not match");
        }
        
		return true;
	}

	/**
	 * Get OAuth JWT token GRANT_TYPE: CLIENT_CREDENTIALS
	 * 
	 * @return
	 */
	private String getKeycloakToken() {
		String tokenEndpointURI = buildTokenEndpoint();
		RestTemplate rest = new RestTemplate();

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<MultiValueMap<String, String>>(initOAuth2RequestHeader(), headers);

		ResponseEntity<String> response = rest.postForEntity(tokenEndpointURI, request, String.class);
		return response.getBody().toString();
	}

	
	
	/**
	 * Get expected signature algorithm from configuration.
	 * 
	 * @param algStr
	 * @return
	 */
	private JWSAlgorithm loadExpectedAlgorithm() {
		switch (config.getJwsAlgorithm()) {
		case "RS256":
			return JWSAlgorithm.RS256;
		default:
			return JWSAlgorithm.RS256;
		}
	}
	
	private String loadJWTIssuer() {
		return config.getTokenIssuer();
	}

	/**
	 * Load IdP configuration
	 * 
	 * @return
	 */
	private MultiValueMap<String, String> initOAuth2RequestHeader() {
		MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();

		map.add("grant_type", config.getGrantType());
		map.add("client_id", config.getClientId());
		map.add("client_secret", config.getClientSecret());

		return map;
	}


	/**
	 * Build keycloak token endpoint
	 * 
	 * @return
	 */
	private String buildTokenEndpoint() {
		String tokenEndpoint = null;
		if (config.getPort() != null && config.getPort().length() > 3) {
			tokenEndpoint = config.getHost() + ":" + config.getPort() + config.getTokenEndpoint();
		} else {
			tokenEndpoint = config.getHost() + config.getTokenEndpoint();
		}

		return tokenEndpoint;
	}

	/**
	 * Build JWKS endpoint URL
	 * 
	 * @return
	 */
	private String buildJWKSEndpoint() {
		String jwksEndpoint = null;
		if (config.getPort() != null && config.getPort().length() > 3) {
			jwksEndpoint = config.getHost() + ":" + config.getPort() + config.getJwksSourceEndpoint();
		} else {
			jwksEndpoint = config.getHost() + config.getJwksSourceEndpoint();
		}

		return jwksEndpoint;
	}
	
	
	/**
	 * Load JWT processor used for token validation.
	 * 
	 * @return
	 */
	private ConfigurableJWTProcessor<SecurityContext> loadJWTProcessor() {

		// JWT processor used for validating signature, expiry date and
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<SecurityContext>();

		// The RemoteJWKSet object used in loadKeySource method caches the retrieved
		// keys from remote
		JWKSource<SecurityContext> jwkSource = loadKeySource();

		// The expected JWS algorithm
		JWSAlgorithm jwsAlgorithm = loadExpectedAlgorithm();

		JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<SecurityContext>(jwsAlgorithm,
				jwkSource);
		jwtProcessor.setJWSKeySelector(keySelector);

		return jwtProcessor;
	}

	/**
	 * Load JWK Source from IdP
	 * 
	 * @return
	 */
	private JWKSource<SecurityContext> loadKeySource() {
		String keySourceUrl = buildJWKSEndpoint();
		JWKSource<SecurityContext> keySource = null;
		try {
			keySource = new RemoteJWKSet<SecurityContext>(new URL(keySourceUrl));
		} catch (MalformedURLException e) {
			logger.error("Cannot load JWKSource from remote", e);
		}
		return keySource;
	}


	
}
