package com.wyrhero.shirodemo.chaper2.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.Realm;

/**
 * 自定义的Realm
 * @author wyrhero
 * @date 20180223
 */
public class MyRealm3 implements Realm{
    private final String name = "MyRealm3";
    private final String defaultUsername = "zhang";
    private final String defaultPassword = "123";

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        //仅支持UsernamePasswordToken 类型的Token
        return token instanceof UsernamePasswordToken;
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String)token.getPrincipal();
        String password = new String((char[])token.getCredentials());
        if(!defaultUsername.equals(username)){
            //用户名错误异常
            throw new UnknownAccountException();
        }
        if(!defaultPassword.equals(password)){
            //密码错误
            throw new IncorrectCredentialsException();
        }
        //如果没报错，身份认证成功，返回一个AuthenticationInfo实现
        return new SimpleAuthenticationInfo(username+"@163.com",password,getName());
    }
}
