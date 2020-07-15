package me.crespel.karaplan.config;

import java.security.Principal;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import me.crespel.karaplan.web.api.ApiController;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig {

	@Bean
	public Docket api() { 
		return new Docket(DocumentationType.SWAGGER_2)  
				.apiInfo(apiInfo())
				.ignoredParameterTypes(Principal.class)
				.select()
				.apis(RequestHandlerSelectors.basePackage(ApiController.class.getPackage().getName()))
				.paths(PathSelectors.any())
				.build();
	}

	private ApiInfo apiInfo() {
		return new ApiInfoBuilder()
				.title("KaraPlan REST API")
				.description("Karaoke Planner web application with song search, ratings, comments, playlists and more.")
				.version("1.0")
				.build();
	}

}
