package me.crespel.karaplan.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import me.crespel.karaplan.security.OidcUserServiceWrapper;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/", "/home").permitAll()
				.antMatchers("/favicon.ico", "/**/*.css", "/**/*.js", "/**/*.js.map", "/webjars/**").permitAll()
				.antMatchers("/api/", "/swagger-ui.html", "/v*/api-docs/**", "/swagger-resources/**", "/csrf").permitAll()
				.antMatchers("/api/v1/account/**").permitAll()
				.antMatchers("/actuator/health", "/actuator/info").permitAll()
				.antMatchers("/actuator/**").hasRole("ADMIN")
				.anyRequest().authenticated()
				.and()
			.csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				.and()
			.oauth2Login()
				.loginPage("/login")
				.permitAll()
				.userInfoEndpoint()
					.oidcUserService(oidcUserService())
					.and()
				.and()
			.exceptionHandling()
				.defaultAuthenticationEntryPointFor(new BearerTokenAuthenticationEntryPoint(), new AntPathRequestMatcher("/api/**"));
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
