package me.crespel.karaplan.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
public class KarafunConfig {

	@Bean
	public KarafunRemoteProperties karafunRemoteProperties() {
		return new KarafunRemoteProperties();
	}

	@Bean
	public KarafunWebProperties karafunWebProperties() {
		return new KarafunWebProperties();
	}

	@Bean
	public KarafunBarProperties karafunBarProperties() {
		return new KarafunBarProperties();
	}

	@Data
	@ConfigurationProperties("karaplan.karafun.remote")
	public static class KarafunRemoteProperties {
		private String endpoint = "https://www.karafun.com";
		private Map<String, String> endpointForLocale = new HashMap<>();
		private Integer remoteId = 123456;
	}

	@Data
	@ConfigurationProperties("karaplan.karafun.web")
	public static class KarafunWebProperties {
		private String endpoint = "https://www.karafun.com";
		private Map<String, String> endpointForLocale = new HashMap<>();
		private String basePath = "/api/";
		private Integer clientId = 7;
		private String clientVersion = "2.1.0";
		private Integer protocol = 1;
		private String key = "zS@nfy_j";
	}

	@Data
	@ConfigurationProperties("karaplan.karafun.bar")
	public static class KarafunBarProperties {
		private String endpoint = "https://www.karafunbar.com/fr/lille/book";
	}

}
