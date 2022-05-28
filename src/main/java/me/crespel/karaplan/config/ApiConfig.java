package me.crespel.karaplan.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;

@Configuration
public class ApiConfig {

	@Bean
	public OpenAPI apiInfo() {
		return new OpenAPI().info(new Info()
				.title("KaraPlan REST API")
				.description("Karaoke Planner web application with song search, ratings, comments, playlists and more.")
				.version("1.0"));
	}

}
