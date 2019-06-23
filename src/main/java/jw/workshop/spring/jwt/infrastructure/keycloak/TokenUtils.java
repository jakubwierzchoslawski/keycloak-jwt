package jw.workshop.spring.jwt.infrastructure.keycloak;

import com.google.gson.Gson;

public class TokenUtils {

	private static Gson gson;

	static {
		gson = new Gson();
	}

	/**
	 * Get Access Token from Keycloak JSON response
	 * 
	 * @param json
	 * @return
	 */
	public static KeycloakTokenResponse tokenObjFromString(String json) {
		return gson.fromJson(json, KeycloakTokenResponse.class);
	}



}