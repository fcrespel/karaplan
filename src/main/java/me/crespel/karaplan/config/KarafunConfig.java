package me.crespel.karaplan.config;

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
	public KarafunBarProperties karafunBarProperties() {
		return new KarafunBarProperties();
	}

	@Data
	@ConfigurationProperties("karaplan.karafun.remote")
	public static class KarafunRemoteProperties {
		private String endpoint = "https://www.karafun.fr";
		private Integer remoteId = 123456;
	}

	@Data
	@ConfigurationProperties("karaplan.karafun.bar")
	public static class KarafunBarProperties {
		private String endpoint = "https://www.karafunbar.com/fr/lille/book";
	}

}
