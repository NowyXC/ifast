package com.ifast.common.config;

import com.google.common.collect.Maps;
import com.ifast.common.utils.SpringContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.ehcache.EhCacheCacheManager;
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean;
import org.springframework.cache.support.AbstractCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.cache.RedisCache;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

/**
 * 缓存配置
 * 策略:
 * 1. 默认ehcache
 * 2. 如果配置spring.redis.host 则使用redis
 */
@Configuration
@EnableCaching
public class CacheConfiguration {

	private static Logger log = LoggerFactory.getLogger(CacheConfiguration.class);


	/** 配置spring.redis.host时使用RedisCacheManager，否则使用EhCacheCacheManager */
	@Bean
    @ConditionalOnProperty(prefix="spring.redis", name="host", havingValue="false", matchIfMissing=true)
	public EhCacheManagerFactoryBean ehCacheManagerFactoryBean() {
		EhCacheManagerFactoryBean cacheManagerFactoryBean = new EhCacheManagerFactoryBean();
		cacheManagerFactoryBean.setConfigLocation(new ClassPathResource("config/ehcache.xml"));
		cacheManagerFactoryBean.setShared(true);
		return cacheManagerFactoryBean;
	}

	/** 不存在则自动创建name的缓存 */
    @Bean
    @ConditionalOnBean(EhCacheManagerFactoryBean.class)
    public EhCacheCacheManager ehCacheCacheManager(EhCacheManagerFactoryBean ehCacheManagerFactoryBean) {
        return new EhCacheCacheManager(ehCacheManagerFactoryBean.getObject()) {
			@Override
			protected Cache getMissingCache(String name) {
				Cache cache = super.getMissingCache(name);
				if (cache == null) {
					//使用default配置克隆缓存
					getCacheManager().addCacheIfAbsent(name);
					cache = super.getCache(name);
				}
				return cache;
			}
        };
    }

    /**
     *  动态配置缓存，
     *  示例：<code>Cache fiveMinutes = CacheConfiguration.dynaConfigCache("5min", 300);</code>
     */
    @SuppressWarnings("unchecked")
    public static Cache dynaConfigCache(String name, long timeToLiveSeconds) {
    	CacheManager cacheManager = SpringContextHolder.getBean(CacheManager.class);
    	if(cacheManager instanceof RedisCacheManager) {
			if(log.isDebugEnabled()){
				log.debug("使用RedisCacheManager");
			}
    		//spring data redis 2.0之前的配置：
//			Field expiresField = ReflectionUtils.findField(RedisCacheManager.class, "expires");
//			ReflectionUtils.makeAccessible(expiresField);
//			Map<String, Long> expires = (Map<String, Long>)ReflectionUtils.getField(expiresField, cacheManager);
//			if(expires == null) {
//				ReflectionUtils.setField(expiresField, cacheManager, expires = new HashMap<>());
//			}
//			expires.put(name, timeToLiveSeconds);

			//spring data redis 2.0 之后的方法
			//(name,timeToLiveSeconds) -> 转RedisCache -> 存入cacheMap -> 更新cacheNames

			//1.(name,timeToLiveSeconds) 转 RedisCache
			//1.1 获取createRedisCache(String name, @Nullable RedisCacheConfiguration cacheConfig)方法
			Method createCacheMethod = ReflectionUtils.findMethod(RedisCacheManager.class,
					"createRedisCache",String.class,RedisCacheConfiguration.class);
			ReflectionUtils.makeAccessible(createCacheMethod);
			RedisCache cache = (RedisCache) ReflectionUtils.invokeMethod(createCacheMethod,cacheManager,name,
					RedisCacheConfiguration.defaultCacheConfig().entryTtl(Duration.ofSeconds(timeToLiveSeconds)));

			//2.获取cacheMap对象
			Field cacheMapField = ReflectionUtils.findField(AbstractCacheManager.class, "cacheMap");
			ReflectionUtils.makeAccessible(cacheMapField);
			ConcurrentMap<String, Cache> cacheMap = (ConcurrentMap<String, Cache>) ReflectionUtils.getField(cacheMapField, cacheManager);

			//3.存入cacheMap
			cacheMap.put(name,cache);

			//4.updateCacheNames(String name)
			Method updateCacheNamesMethod = ReflectionUtils.findMethod(AbstractCacheManager.class,
					"updateCacheNames",String.class);
			ReflectionUtils.makeAccessible(updateCacheNamesMethod);
			ReflectionUtils.invokeMethod(updateCacheNamesMethod,cacheManager,name);

			if(log.isDebugEnabled()){
				Map<String, RedisCacheConfiguration> cacheConfigurations = ((RedisCacheManager) cacheManager).getCacheConfigurations();
				for(Map.Entry<String,RedisCacheConfiguration> entry:cacheConfigurations.entrySet()){
					log.debug("RedisCache信息:key:{},ttl:{}",entry.getKey(),entry.getValue().getTtl().toString());
				}
			}
		}else if(cacheManager instanceof EhCacheCacheManager) {
			if(log.isDebugEnabled()){
				log.debug("使用EhCacheCacheManager");
			}
			net.sf.ehcache.Cache ehCacheCache = (net.sf.ehcache.Cache)cacheManager.getCache(name).getNativeCache();
    		net.sf.ehcache.config.CacheConfiguration cacheConfiguration = ehCacheCache.getCacheConfiguration();
    		cacheConfiguration.timeToLiveSeconds(timeToLiveSeconds);
    	}
    	return cacheManager.getCache(name);
    }
}