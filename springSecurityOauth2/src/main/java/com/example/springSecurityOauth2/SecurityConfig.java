package com.example.springSecurityOauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	/*
	 * @Bean SecurityFilterChain securityFilterChain(HttpSecurity http) throws
	 * Exception {
	 * 
	 * http // ... .authorizeHttpRequests(authorize -> authorize
	 * .requestMatchers("/**","/resources/**", "/signup", "/about").permitAll()
	 * .requestMatchers("/admin/**").hasRole("ADMIN")
	 * .requestMatchers("/db/**").access(AuthorizationManagers.allOf(
	 * AuthorityAuthorizationManager.hasRole("ADMIN"),
	 * AuthorityAuthorizationManager.hasRole("DBA"))) .anyRequest().denyAll() );
	 * 
	 * return http.build(); }
	 * 
	 * @Bean UserDetailsService userDetailsService() { UserDetails user =
	 * User.builder() .username("user") .password("password") .roles("USER")
	 * .build(); UserDetails admin = User.builder() .username("admin")
	 * .password("password") .roles("ADMIN", "USER") .build(); return new
	 * InMemoryUserDetailsManager(user, admin); }
	 */

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.oauth2Login(Customizer.withDefaults()).build();
	}
	
	@Bean
	ClientRegistrationRepository clientRegistrationRepository() {
		
		return new InMemoryClientRegistrationRepository(clientRegistration());
	}
	
	private ClientRegistration clientRegistration() {
        return ClientRegistration.withRegistrationId("xtg")
            .clientId("xtg-client-id")
            .clientSecret("xtg-client-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/login/oauth2/code/{registrationId}")
            .scope("openid", "profile", "email", "address", "phone")
            .authorizationUri("http://localhost:8080/o/oauth2/v2/auth")
            .tokenUri("http://localhost:8080/oauth2/v4/token")
            .userInfoUri("http://localhost:8080/oauth2/v3/userinfo")
            .userNameAttributeName(IdTokenClaimNames.SUB)
            .jwkSetUri("http://localhost:8080/oauth2/v3/certs")
            .clientName("xtg")
            .build();
    }

	/*
	 * private ClientRegistration clientRegistration() { return
	 * ClientRegistration.withRegistrationId("google") .clientId("google-client-id")
	 * .clientSecret("google-client-secret")
	 * .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	 * .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	 * .redirectUri("http://localhost:8080/login/oauth2/code/{registrationId}")
	 * .scope("openid", "profile", "email", "address", "phone")
	 * .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
	 * .tokenUri("https://www.googleapis.com/oauth2/v4/token")
	 * .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
	 * .userNameAttributeName(IdTokenClaimNames.SUB)
	 * .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
	 * .clientName("Google") .build(); }
	 */
	
	/*
	 * @Bean public SecurityFilterChain filterChain(HttpSecurity http) throws
	 * Exception { http .oauth2Client(oauth2 -> oauth2
	 * .clientRegistrationRepository(this.clientRegistrationRepository())
	 * .authorizedClientRepository(this.authorizedClientRepository())
	 * .authorizedClientService(this.authorizedClientService())
	 * .authorizationCodeGrant(codeGrant -> codeGrant
	 * .authorizationRequestRepository(this.authorizationRequestRepository())
	 * .authorizationRequestResolver(this.authorizationRequestResolver())
	 * .accessTokenResponseClient(this.accessTokenResponseClient()) ) ); return
	 * http.build(); }
	 */

	/*
	 * @Bean public OAuth2AuthorizedClientManager authorizedClientManager(
	 * ClientRegistrationRepository clientRegistrationRepository,
	 * OAuth2AuthorizedClientRepository authorizedClientRepository) {
	 * 
	 * OAuth2AuthorizedClientProvider authorizedClientProvider =
	 * OAuth2AuthorizedClientProviderBuilder.builder() .authorizationCode()
	 * .refreshToken() .clientCredentials() .password() .build();
	 * 
	 * DefaultOAuth2AuthorizedClientManager authorizedClientManager = new
	 * DefaultOAuth2AuthorizedClientManager( clientRegistrationRepository,
	 * authorizedClientRepository);
	 * authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider)
	 * ;
	 * 
	 * return authorizedClientManager; }
	 */

	/*
	 * // @Bean // public SecurityFilterChain securityFilterChain(HttpSecurity http)
	 * throws Exception { // http // .authorizeHttpRequests(authorize -> authorize
	 * // .requestMatchers("/", "/login**").permitAll() //
	 * .anyRequest().authenticated() // ) //
	 * .oauth2Login(Customizer.withDefaults()); // return http.build(); // }
	 */
}
