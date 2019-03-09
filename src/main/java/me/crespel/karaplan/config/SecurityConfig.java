package me.crespel.karaplan.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/").permitAll()
				.antMatchers("/**/*.css", "/**/*.js", "/**/*.js.map", "/webjars/**").permitAll()
				.antMatchers("/api/", "/swagger-ui.html", "/v*/api-docs/**", "/swagger-resources/**", "/csrf").permitAll()
				.antMatchers("/actuator/health", "/actuator/info").permitAll()
				.antMatchers("/actuator/**").hasRole("ADMIN")
				.anyRequest().authenticated()
				.and()
			.csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				.and()
			.oauth2Login();
	}

}
