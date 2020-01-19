package me.crespel.karaplan.config;

import static com.google.common.collect.Lists.newArrayList;
import static springfox.documentation.schema.AlternateTypeRules.newRule;

import java.lang.reflect.Type;
import java.security.Principal;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.data.domain.Pageable;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;

import com.fasterxml.classmate.TypeResolver;

import springfox.documentation.builders.AlternateTypeBuilder;
import springfox.documentation.builders.AlternateTypePropertyBuilder;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.schema.AlternateTypeRule;
import springfox.documentation.schema.AlternateTypeRuleConvention;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2WebMvc;

@Configuration
@EnableSwagger2WebMvc
public class SwaggerConfig {

	@Bean
	public Docket api() { 
		return new Docket(DocumentationType.SWAGGER_2)  
				.apiInfo(apiInfo())
				.ignoredParameterTypes(Principal.class)
				.select()
				.apis(RequestHandlerSelectors.any())
				.paths(PathSelectors.ant("/api/**"))
				.build();
	}

	private ApiInfo apiInfo() {
		return new ApiInfoBuilder()
				.title("KaraPlan REST API")
				.description("All operations are exposed as JSON and require an OAuth 2.0 Access Token granted by the configured OAuth Authorization Server.")
				.version("1.0")
				.build();
	}

	/* Pageable interface support from springfox.documentation.spring.data.rest.configuration.SpringDataRestConfiguration */

	@Bean
	public AlternateTypeRuleConvention pageableConvention(
			final TypeResolver resolver,
			final RepositoryRestConfiguration restConfiguration) {
		return new AlternateTypeRuleConvention() {

			@Override
			public int getOrder() {
				return Ordered.HIGHEST_PRECEDENCE;
			}

			@Override
			public List<AlternateTypeRule> rules() {
				return newArrayList(
						newRule(resolver.resolve(Pageable.class), resolver.resolve(pageableMixin(restConfiguration)))
				);
			}
		};
	}

	private Type pageableMixin(RepositoryRestConfiguration restConfiguration) {
		return new AlternateTypeBuilder()
				.fullyQualifiedClassName(
						String.format("%s.generated.%s",
								Pageable.class.getPackage().getName(),
								Pageable.class.getSimpleName()))
				.withProperties(newArrayList(
						property(Integer.class, restConfiguration.getPageParamName()),
						property(Integer.class, restConfiguration.getLimitParamName()),
						property(String.class, restConfiguration.getSortParamName())
				))
				.build();
	}

	private AlternateTypePropertyBuilder property(Class<?> type, String name) {
		return new AlternateTypePropertyBuilder()
				.withName(name)
				.withType(type)
				.withCanRead(true)
				.withCanWrite(true);
	}

}
