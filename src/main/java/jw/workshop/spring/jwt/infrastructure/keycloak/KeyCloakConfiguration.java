package jw.workshop.spring.jwt.infrastructure.keycloak;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import lombok.Data;

@Data
@Configuration
@PropertySource(name = "keycloak", value = "classpath:keycloak.properties", encoding="UTF-8")
public class KeyCloakConfiguration {

	@Value("${keycloak.clientId}")
	private String clientId;

	@Value("${keycloak.clientSecret}")
	private String clientSecret;

	@Value("${keycloak.host}")
	private String host;

	@Value("${keycloak.port}")
	private String port;
	
	@Value("${keycloak.oauth2.grantType}")
	private String grantType;
	
	@Value("${keycloak.oauth2.tokenEndpoint}")
	private String tokenEndpoint;

	@Value("${keycloak.oauth2.jwksSourceEndpoint}")
	private String jwksSourceEndpoint;
	
	@Value("${keycloak.oauth2.jwsAlgorithm}")
	private String jwsAlgorithm;
	
	@Value("${keycloak.oauth2.tokenIssuer}")
	private String tokenIssuer;
	
	
	

	public void init(String clientId, String clientSecret, String host, String port) {
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.host = host;
		this.port = port;
	}

}
