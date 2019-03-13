package me.crespel.karaplan.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.ForwardedHeaderFilter;

@Configuration
public class WebConfig {

	@Bean
	public FilterRegistrationBean<ForwardedHeaderFilter> forwardedHeaderFilter() {
		FilterRegistrationBean<ForwardedHeaderFilter> registration = new FilterRegistrationBean<>();
		registration.setFilter(new ForwardedHeaderFilter());
		registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return registration;
	}

}
