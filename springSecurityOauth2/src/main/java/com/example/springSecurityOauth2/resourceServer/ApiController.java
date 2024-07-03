package com.example.springSecurityOauth2.resourceServer;

import java.security.Principal;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@RestController
@RequestMapping("/api")
public class ApiController {

	private final String SECRATE_KEY = "f53398d050ff53baede56ce647fe606bd44856a825ee7478d3ba8069df3b2bf3";

	@GetMapping("/public")
	public String publicEndpoint() {
		return "This is a public endpoint " + getJWTToken("gopal");
	}

	@GetMapping("/private")
	public String privateEndpoint(Principal principal) {
		return "This is a private endpoint. Hello, " + principal.getName();
	}

	@GetMapping("/myapp")
	public String myapp() {
		System.out.println("My app");
		return "This is a myapp endpoint";
	}

	private String getJWTToken(String username) {
		String secretKey = "mySecretKey";
		List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER");

		String token = Jwts.builder().subject("subject")
				.claim("authorities",
						grantedAuthorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
				.issuedAt(new Date())
				// .expiration(new Date(System.currentTimeMillis()))
				.signWith(getSignKey()).compact();

		return "Bearer " + token;
	}

	private SecretKey getSignKey() {
		String secretKey = "mySecretKey";
		// TODO Auto-generated method stub
		byte[] keyBytes = Decoders.BASE64URL.decode(SECRATE_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}