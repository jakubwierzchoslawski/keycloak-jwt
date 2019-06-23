package jw.workshop.spring.jwt.infrastructure.keycloak;

import com.google.gson.annotations.SerializedName;

import jw.workshop.spring.jwt.model.TokenResponse;
import lombok.Data;

@Data
public class KeycloakTokenResponse extends TokenResponse{
	
	@SerializedName("refresh_expires_in") 
	private String refreshExpiresIn;
	@SerializedName("not_before_policy") 
	private String notBeforePolicy;
	@SerializedName("session_state") 
	private String sessionState;

}
