package me.crespel.karaplan.config;

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
		private String endpoint = "https://www.version-karaoke.fr/api";
		private Integer affiliateId = 77;
	}

}
