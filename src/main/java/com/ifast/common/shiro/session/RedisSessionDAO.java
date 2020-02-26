package com.ifast.common.shiro.session;

import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;

/**
 * <pre>
 * 主要定义了在缓存中保存session，更新，删除，读取，获取所有的集合等操作。
 *  activeSessionsCacheName 设置Session缓存名字,默认就是shiro-activeSessionCache
 * </pre>
 * <small> 2018/8/21 16:29 | Aron</small>
 */
public class RedisSessionDAO extends EnterpriseCacheSessionDAO {

    private String activeSessionsCacheName;

    public RedisSessionDAO(String activeSessionsCacheName) {
        this.activeSessionsCacheName = activeSessionsCacheName;
    }

    @Override
    public String getActiveSessionsCacheName() {
        return this.activeSessionsCacheName;
    }
}
