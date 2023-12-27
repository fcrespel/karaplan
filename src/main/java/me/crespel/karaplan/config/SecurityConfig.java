package me.crespel.karaplan.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import me.crespel.karaplan.security.OAuth2UserServiceWrapper;
import me.crespel.karaplan.security.OidcUserServiceWrapper;

@Configuration
public class SecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();
		csrfHandler.setCsrfRequestAttributeName(null); // Force loading CSRF token on every request
		return http
			.authorizeHttpRequests(requests -> requests
				.requestMatchers("/", "/home").permitAll()
				.requestMatchers("/*.css", "/*.js", "/*.js.map", "/*.jpg", "/*.png", "/*.svg", "/*.ico", "/assets/**", "/webjars/**", "/site.webmanifest", "/browserconfig.xml").permitAll()
				.requestMatchers("/api", "/v3/api-docs/**", "/swagger-resources/**", "/swagger-ui/**", "/csrf").permitAll()
				.requestMatchers("/api/v1/account/**").permitAll()
				.requestMatchers("/actuator/health", "/actuator/health/liveness", "/actuator/health/readiness", "/actuator/info").permitAll()
				.requestMatchers("/actuator/**").hasRole("ADMIN")
				.requestMatchers("/login").permitAll()
				.requestMatchers("/_ah/**").permitAll()
				.anyRequest().authenticated())
			.csrf(csrf -> csrf
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				.csrfTokenRequestHandler(csrfHandler))
			.oauth2Login(login -> login
				.loginPage("/login")
				.userInfoEndpoint(userinfo -> userinfo
					.userService(oauth2UserService())
					.oidcUserService(oidcUserService())))
			.exceptionHandling(handling -> handling
				.defaultAuthenticationEntryPointFor(new BearerTokenAuthenticationEntryPoint(), new AntPathRequestMatcher("/api/**")))
			.build();
	}

	@Bean
	public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
		return new OAuth2UserServiceWrapper(new DefaultOAuth2UserService());
	}

	@Bean
	public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		return new OidcUserServiceWrapper(new OidcUserService());
	}

	@Bean
	public HttpFirewall httpFirewall() {
		StrictHttpFirewall firewall = new StrictHttpFirewall();
		firewall.setAllowSemicolon(true);
		return firewall;
	}

}
