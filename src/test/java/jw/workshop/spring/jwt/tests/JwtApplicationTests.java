package jw.workshop.spring.jwt.tests;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import jw.workshop.spring.jwt.model.api.IdentityProvider;

@RunWith(SpringRunner.class)
@SpringBootTest
public class JwtApplicationTests {

	
	@Autowired
	private IdentityProvider keycloakService;
	
	@Test
	public void contextLoads() {
	}
	
	
	/**
	 * Happy scenario
	 */
	@Test
	public void testGetToken() {
		String token = keycloakService.getAccessToken();
		
		assertNotNull(token);
		assertTrue(keycloakService.validateToken(token));
		
	}

}
