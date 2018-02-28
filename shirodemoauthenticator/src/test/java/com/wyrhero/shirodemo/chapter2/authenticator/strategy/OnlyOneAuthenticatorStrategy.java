package com.wyrhero.shirodemo.chapter2.authenticator.strategy;


import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.pam.AbstractAuthenticationStrategy;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.util.CollectionUtils;

import java.util.Collection;

public class OnlyOneAuthenticatorStrategy extends AbstractAuthenticationStrategy {

    @Override
    public AuthenticationInfo beforeAllAttempts(Collection<? extends Realm> realms, AuthenticationToken token) throws AuthenticationException {
        //返回一个权限的认证信息
        return new SimpleAuthenticationInfo();
    }

    @Override
    public AuthenticationInfo beforeAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException {
        //返回之前的合并
        return aggregate;
    }

    @Override
    public AuthenticationInfo afterAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo singleRealmInfo, AuthenticationInfo aggregateInfo, Throwable t) throws AuthenticationException {

        //只有一个的时候，直接返回，多个的时候抛异常
        if(null == singleRealmInfo) {
            return aggregateInfo;
        }

        if(null == aggregateInfo){
            return aggregateInfo;
        } else {
            AuthenticationInfo info =merge(singleRealmInfo,aggregateInfo);
            if(info.getPrincipals().getRealmNames().size() > 1) {
                throw new AuthenticationException("Authentication token of type " + token.getClass() + "] " +
                        "could not be authenticated by any configured realms.   Please ensure that only one realm can " +
                        "authenticate these tokens.");
            }
            return info;
        }

    }

    @Override
    public AuthenticationInfo afterAllAttempts(AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException {
        return aggregate;
    }
}
