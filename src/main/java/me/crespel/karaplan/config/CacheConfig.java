package me.crespel.karaplan.config;

import java.io.Serializable;
import java.lang.reflect.Method;

import org.springframework.cache.annotation.CachingConfigurerSupport;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.interceptor.KeyGenerator;
import org.springframework.cache.interceptor.SimpleKeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableCaching
public class CacheConfig extends CachingConfigurerSupport {

	@Bean
	public KeyGenerator keyGenerator() {
		return new MethodAndArgsKeyGenerator();
	}

	public static class MethodAndArgsKeyGenerator implements KeyGenerator {

		@Override
		public Object generate(Object target, Method method, Object... params) {
			return new MethodAndArgsKey(method, SimpleKeyGenerator.generateKey(params));
		}

	}

	public static class MethodAndArgsKey implements Serializable {

		private Method method;
		private Object paramsKey;

		public MethodAndArgsKey(Method method, Object paramsKey) {
			this.method = method;
			this.paramsKey = paramsKey;
		}

		@Override
		public boolean equals(Object other) {
			return this == other || (other instanceof MethodAndArgsKey &&
					this.method.equals(((MethodAndArgsKey)other).method) &&
					this.paramsKey.equals(((MethodAndArgsKey)other).paramsKey));
		}

		@Override
		public int hashCode() {
			return 31 * method.hashCode() + paramsKey.hashCode();
		}

	}

}
