package me.crespel.karaplan.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
public class KvConfig {

	@Bean
	public KvProperties kvProperties() {
		return new KvProperties();
	}

	@Data
	@ConfigurationProperties("karaplan.kv")
	public static class KvProperties {
		private String endpoint = "https://www.karaoke-version.com/api";
		private Map<String, String> endpointForLocale = new HashMap<>();
		private String userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";
		private Integer affiliateId = 77;
	}

}
