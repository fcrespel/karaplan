package me.crespel.karaplan.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
public class KVConfig {

	@Bean
	public KVProperties kvProperties() {
		return new KVProperties();
	}

	@Data
	@ConfigurationProperties("karaplan.kv")
	public static class KVProperties {
		private String endpoint = "https://www.version-karaoke.fr/api";
		private Integer affiliateId = 77;
	}

}
