package me.crespel.karaplan.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
public class KarafunWebConfig {

	@Bean
	public KarafunWebProperties karafunWebProperties() {
		return new KarafunWebProperties();
	}

	@Data
	@ConfigurationProperties("karaplan.karafun.web")
	public static class KarafunWebProperties {
		private String endpoint = "https://www.karafun.com/api";
		private Map<String, String> endpointForLocale = new HashMap<>();
		private String userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";
		private Integer clientId = 7;
		private String clientVersion = "2.1.0";
		private Integer protocol = 1;
		private String key = "zS@nfy_j";
	}

}
