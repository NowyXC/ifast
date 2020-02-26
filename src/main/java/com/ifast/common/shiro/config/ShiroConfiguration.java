package com.ifast.common.shiro.config;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import com.ifast.api.shiro.JWTAuthenticationFilter;
import com.ifast.api.shiro.JWTAuthorizingRealm;
import com.ifast.common.shiro.cache.SpringCacheManagerWrapper;
import com.ifast.common.shiro.session.RedisSessionDAO;
import com.ifast.common.utils.SpringContextHolder;
import com.ifast.sys.config.BDSessionListener;
import com.ifast.sys.service.MenuService;
import com.ifast.sys.service.RoleService;
import com.ifast.sys.service.UserService;
import com.ifast.sys.shiro.SysUserAuthorizingRealm;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import javax.servlet.Filter;
import java.util.*;

/**
 * <pre>
 * . cache ehcache
 * . realm(cache)
 * . securityManager（realm）
 * . ShiroFilterFactoryBean 注册
 * 
 * </pre>
 * <small> 2018年4月18日 | Aron</small>
 */
@Configuration
public class ShiroConfiguration {


    @Bean
    SessionDAO sessionDAO(ShiroProperties config) {//自定义sessionDAO
        RedisSessionDAO sessionDAO = new RedisSessionDAO(config.getSessionKeyPrefix());
        return sessionDAO;
    }

    //自定义会话Cookie模板
    @Bean
    public SimpleCookie sessionIdCookie(ShiroProperties shiroConfigProperties) {
        return new SimpleCookie(shiroConfigProperties.getJsessionidKey());//声明cooike中session的名称
    }

    @Bean
    public RedisTemplate<Object, Object> redisTemplate( RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<Object, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        return template;
    }


    /**
     * shiro session的管理
     */
    @Bean
    public SessionManager sessionManager(SessionDAO sessionDAO, SimpleCookie simpleCookie) {
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        sessionManager.setSessionIdCookie(simpleCookie);

        Collection<SessionListener> sessionListeners = new ArrayList<>();
        sessionListeners.add(new BDSessionListener());//session数量监听
        sessionManager.setSessionListeners(sessionListeners);
        sessionManager.setSessionDAO(sessionDAO);
        return sessionManager;
    }

    /**
     * shiroCacheManager 缓存管理器
     * 先加载{"springContextHolder","cacheConfiguration"}，再加载shiroCacheManager
     * 主要为了通过cacheConfiguration获取缓存配置
     *      1.默认ehcache
     *      2.如果配置spring.redis.host 则使用redis
     * @return CacheManager缓存管理器
     */
    @Bean(name="shiroCacheManager")
    @DependsOn({"springContextHolder","cacheConfiguration"})
    public CacheManager cacheManager() {
    	SpringCacheManagerWrapper springCacheManager = new SpringCacheManagerWrapper();
    	org.springframework.cache.CacheManager cacheManager = SpringContextHolder.getBean(org.springframework.cache.CacheManager.class);
    	springCacheManager.setCacheManager(cacheManager);
        return springCacheManager;
    }

    //jwt的realm（安全数据库）
    @Bean
    JWTAuthorizingRealm jwtAuthorizingRealm(MenuService menuService, RoleService roleService){
        JWTAuthorizingRealm realm = new JWTAuthorizingRealm(menuService, roleService);
        realm.setCachingEnabled(true);
        realm.setAuthorizationCachingEnabled(true);
        return realm;
    }

    //系统用户授权的realm（安全数据库）
    @Bean
    SysUserAuthorizingRealm sysUserAuthorizingRealm(MenuService menuService, RoleService roleService, UserService userService){
        SysUserAuthorizingRealm realm = new SysUserAuthorizingRealm(menuService, roleService, userService);
        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName(Sha256Hash.ALGORITHM_NAME);
        realm.setCredentialsMatcher(credentialsMatcher);
        realm.setCachingEnabled(true);
        realm.setAuthorizationCachingEnabled(true);
        return realm;
    }


    //配置安全管理器
    @Bean
    SecurityManager securityManager(SessionManager sessionManager , CacheManager cacheManager, JWTAuthorizingRealm realm1, SysUserAuthorizingRealm realm2) {
        //使用默认的安全管理器
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        // 自定义缓存实现,默认采用ehcache，存在redis则用redis
        manager.setCacheManager(cacheManager);
        //将自定义的realm交给安全管理器统一调度管理
        manager.setRealms(Arrays.asList(realm1, realm2));
        // 自定义session管理
        manager.setSessionManager(sessionManager);
        return manager;
    }

    @Bean
    ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager, UserService userService) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        
        // 添加jwt过滤器，/api/** 相关路径直接走jwt过滤器
        Map<String, Filter> filterMap = new HashMap<>();
        filterMap.put("jwt", new JWTAuthenticationFilter(userService, "/api/user/login"));
        shiroFilterFactoryBean.setFilters(filterMap);
        
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        shiroFilterFactoryBean.setLoginUrl("/login");
        shiroFilterFactoryBean.setSuccessUrl("/index");
        shiroFilterFactoryBean.setUnauthorizedUrl("/shiro/405");


        LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        // 微信对接
        filterChainDefinitionMap.put("/wx/mp/msg/**", "anon");
        // api
        filterChainDefinitionMap.put("/api/user/refresh", "anon");
        filterChainDefinitionMap.put("/api/**", "jwt");
        // email
        filterChainDefinitionMap.put("/emil/**", "anon");

        filterChainDefinitionMap.put("/doc.html**", "anon");
        filterChainDefinitionMap.put("/swagger-resources/**", "anon");
        filterChainDefinitionMap.put("/webjars/**", "anon");
        filterChainDefinitionMap.put("/v2/**", "anon");
        filterChainDefinitionMap.put("/shiro/**", "anon");
        filterChainDefinitionMap.put("/login", "anon");
        filterChainDefinitionMap.put("/css/**", "anon");
        filterChainDefinitionMap.put("/js/**", "anon");
        filterChainDefinitionMap.put("/fonts/**", "anon");
        filterChainDefinitionMap.put("/img/**", "anon");
        filterChainDefinitionMap.put("/docs/**", "anon");
        filterChainDefinitionMap.put("/druid/**", "anon");
        filterChainDefinitionMap.put("/upload/**", "anon");
        filterChainDefinitionMap.put("/files/**", "anon");
        filterChainDefinitionMap.put("/test/**", "anon");
        filterChainDefinitionMap.put("/tt/**", "anon");
        filterChainDefinitionMap.put("/logout", "logout");
        filterChainDefinitionMap.put("/", "anon");
        filterChainDefinitionMap.put("/**", "authc");

        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }

    //管理shiro bean生命周期
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    //处理注解不生效问题
    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator proxyCreator = new DefaultAdvisorAutoProxyCreator();
        proxyCreator.setProxyTargetClass(true);
        return proxyCreator;
    }

    //配置前台thymeleaf标签
    @Bean
    public ShiroDialect shiroDialect() {
        return new ShiroDialect();
    }

    //配置shiro注解支持
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

}
