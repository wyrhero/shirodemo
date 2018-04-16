package com.wyrhero.shirodemo.chapter3.authorizer;

import org.apache.shiro.authz.UnauthorizedException;
import org.junit.Assert;
import org.junit.Test;

public class PermissionTest extends BaseTest{
    @Test
    public void tetIsPermitted(){
        login("classpath:shiro-permission.ini","zhang","123");
        //判断拥有权限: user:create
        Assert.assertTrue(subject().isPermitted("user:create"));
        //判断用户有权限： user:update and user:delete
        Assert.assertTrue(subject().isPermittedAll("user:create","user:delete"));
        //判断有没有权限： user:view
        Assert.assertFalse(subject().isPermitted("user:view"));
    }

    @Test(expected= UnauthorizedException.class)
    public void testCheckPermission(){
        login("classpath:shiro-permission.ini","zhang","123");
        //检查有权限： user:create
        subject().checkPermission("user:create");
        //检查有权限：user:delete and user:update
        subject().checkPermissions("user:delete","user:update");
        //检查拥有权限： user:view 失败抛出异常
        subject().checkPermission("user:view");
    }
}
