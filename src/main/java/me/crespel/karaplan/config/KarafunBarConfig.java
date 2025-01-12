package me.crespel.karaplan.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
public class KarafunBarConfig {

	@Bean
	public KarafunBarProperties karafunBarProperties() {
		return new KarafunBarProperties();
	}

	@Data
	@ConfigurationProperties("karaplan.karafun.bar")
	public static class KarafunBarProperties {
		private String endpoint = "https://www.karafunbar.com/fr/lille/book";
		private long connectTimeout = 10000;
		private long readTimeout = 30000;
		private String userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";
	}

}
