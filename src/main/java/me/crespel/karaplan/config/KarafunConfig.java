package me.crespel.karaplan.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
public class KarafunConfig {

	@Bean
	public KarafunProperties karafunProperties() {
		return new KarafunProperties();
	}

	@Data
	@ConfigurationProperties("karaplan.karafun")
	public static class KarafunProperties {
		private String endpoint = "https://www.karafun.fr";
		private Integer remoteId = 123456;
	}

}
