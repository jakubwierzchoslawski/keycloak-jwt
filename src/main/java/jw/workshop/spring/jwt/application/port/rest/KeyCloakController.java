package jw.workshop.spring.jwt.application.port.rest;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/kc")
public class KeyCloakController {

	
	
	@PostMapping("/token")
	public String getAccessToken() {
		return "";
	}
	
	@PostMapping("/validate")
	public boolean validateToken() {
		return true;
	}
}
