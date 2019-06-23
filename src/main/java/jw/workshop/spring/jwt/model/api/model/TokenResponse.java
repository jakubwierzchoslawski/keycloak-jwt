package jw.workshop.spring.jwt.model.api.model;

import com.google.gson.annotations.SerializedName;

import lombok.Data;

@Data
public class TokenResponse {
	
	@SerializedName("access_token") 
	private String accessToken;
	@SerializedName("expires_in") 
	private String expiresIn;
	@SerializedName("refresh_token") 
	private String refreshToken;
	@SerializedName("token_type") 
	private String tokenType;
	private String scope;

}
