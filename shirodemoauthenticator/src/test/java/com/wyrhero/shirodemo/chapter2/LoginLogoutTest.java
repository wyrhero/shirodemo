package com.wyrhero.shirodemo.chapter2;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

public class LoginLogoutTest {

    /**
     * 测试shiro的授权,权限数据源存放在ini文件中
     */
    @Test
    public void testHelloWorld(){
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        //2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang","123");

        //4、登录，即身份验证
        try{
            subject.login(token);
        } catch (AuthenticationException e){
            //5、身份验证失败
        }

        //断言成功登陆
        Assert.assertTrue(subject.isAuthenticated());

        //6、退出
        subject.logout();

    }

    /**
     * 测试shiro的授权,权限数据源写死在自己实现的单个Realm中
     */
    @Test
    public void testCustomRealm(){
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-realm.ini");
        //2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang","123");

        //4、登录，即身份验证
        try {
            subject.login(token);
        }catch (AuthenticationException e) {
            //5、身份验证失败
        }

        //断言成功登陆
        Assert.assertTrue(subject.isAuthenticated());

        //6、退出
        subject.logout();
    }

    /**
     * 测试shiro的授权,权限数据源写死在自己实现的多个Realm中
     */
    @Test
    public void testMultiCustomRealm(){
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-multi-realm.ini");
        //2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang","123");

        //4、登录，即身份验证
        try {
            subject.login(token);
        }catch (AuthenticationException e) {
            //5、身份验证失败
        }

        //断言成功登陆
        Assert.assertTrue(subject.isAuthenticated());

        //6、退出
        subject.logout();
    }

    /**
     * 测试shiro的授权,权限数据源写到jdbc的realm中
     */
    @Test
    public void testJdbcCustomRealm(){
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-jdbc-realm.ini");
        //2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang","123");

        //4、登录，即身份验证
        try {
            subject.login(token);
        }catch (AuthenticationException e) {
            //5、身份验证失败
        }

        //断言成功登陆
        Assert.assertTrue(subject.isAuthenticated());

        //6、退出
        subject.logout();
    }

    @After
    public void tearDown() throws Exception {
        ThreadContext.unbindSubject();//退出时请解除绑定Subject到线程 否则对下次测试造成影响
    }
}
