package me.crespel.karaplan.config;

import java.io.Serializable;
import java.lang.reflect.Method;

import org.springframework.cache.annotation.CachingConfigurer;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.interceptor.KeyGenerator;
import org.springframework.cache.interceptor.SimpleKeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableCaching
public class CacheConfig implements CachingConfigurer {

	@Bean
	public KeyGenerator keyGenerator() {
		return new MethodAndArgsKeyGenerator();
	}

	public static class MethodAndArgsKeyGenerator implements KeyGenerator {

		@Override
		public Object generate(Object target, Method method, Object... params) {
			return new MethodAndArgsKey(method.toString(), SimpleKeyGenerator.generateKey(params));
		}

	}

	public static class MethodAndArgsKey implements Serializable {

		private String methodKey;
		private Object paramsKey;

		public MethodAndArgsKey(String methodKey, Object paramsKey) {
			this.methodKey = methodKey;
			this.paramsKey = paramsKey;
		}

		@Override
		public boolean equals(Object other) {
			return this == other || (other instanceof MethodAndArgsKey &&
					this.methodKey.equals(((MethodAndArgsKey)other).methodKey) &&
					this.paramsKey.equals(((MethodAndArgsKey)other).paramsKey));
		}

		@Override
		public int hashCode() {
			return 31 * methodKey.hashCode() + paramsKey.hashCode();
		}

	}

}
