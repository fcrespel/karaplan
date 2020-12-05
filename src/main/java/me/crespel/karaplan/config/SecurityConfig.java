package me.crespel.karaplan.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import me.crespel.karaplan.security.OAuth2UserServiceWrapper;
import me.crespel.karaplan.security.OidcUserServiceWrapper;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/", "/home").permitAll()
				.antMatchers("/**/*.css", "/**/*.js", "/**/*.js.map", "/**/*.jpg", "/**/*.png", "/**/*.svg", "/**/*.ico", "/webjars/**", "/site.webmanifest", "/browserconfig.xml").permitAll()
				.antMatchers("/api", "/v*/api-docs/**", "/swagger-resources/**", "/swagger-ui/**", "/csrf").permitAll()
				.antMatchers("/api/v1/account/**").permitAll()
				.antMatchers("/actuator/health", "/actuator/health/liveness", "/actuator/health/readiness", "/actuator/info").permitAll()
				.antMatchers("/actuator/**").hasRole("ADMIN")
				.antMatchers("/_ah/**").permitAll()
				.anyRequest().authenticated()
				.and()
			.csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				.and()
			.oauth2Login()
				.loginPage("/login")
				.permitAll()
				.userInfoEndpoint()
					.userService(oauth2UserService())
					.oidcUserService(oidcUserService())
					.and()
				.and()
			.exceptionHandling()
				.defaultAuthenticationEntryPointFor(new BearerTokenAuthenticationEntryPoint(), new AntPathRequestMatcher("/api/**"));
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
