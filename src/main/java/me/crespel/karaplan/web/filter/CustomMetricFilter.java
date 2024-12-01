package me.crespel.karaplan.web.filter;

import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.Meter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class CustomMetricFilter extends GenericFilterBean {

	private final LongCounter apiCallsCounter;

	public CustomMetricFilter(OpenTelemetry otel) {
		Meter meter = otel.getMeter("karaplan");
		this.apiCallsCounter = meter.counterBuilder("karaplan.api.calls").setDescription("Number of KaraPlan API calls").build();
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		if (httpRequest.getRequestURI() != null && httpRequest.getRequestURI().startsWith("/api/")) {
			Attributes attrs = Attributes.builder().put("method", httpRequest.getMethod()).build();
			apiCallsCounter.add(1, attrs);
		}
		chain.doFilter(request, response);
	}

}
