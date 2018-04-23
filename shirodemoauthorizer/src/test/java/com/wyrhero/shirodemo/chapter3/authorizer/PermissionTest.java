package com.wyrhero.shirodemo.chapter3.authorizer;

import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.junit.Assert;
import org.junit.Test;

public class PermissionTest extends BaseTest {
    @Test
    public void tetIsPermitted() {
        login("classpath:shiro-permission.ini", "zhang", "123");
        //判断拥有权限: user:create
        Assert.assertTrue(subject().isPermitted("user:create"));
        //判断用户有权限： user:update and user:delete
        Assert.assertTrue(subject().isPermittedAll("user:create", "user:delete"));
        //判断有没有权限： user:view
        Assert.assertFalse(subject().isPermitted("user:view"));
    }

    @Test(expected = UnauthorizedException.class)
    public void testCheckPermission() {
        login("classpath:shiro-permission.ini", "zhang", "123");
        //检查有权限： user:create
        subject().checkPermissions("user:create");
        //检查有权限：user:delete and user:update
        subject().checkPermissions("user:delete", "user:update");
        //检查拥有权限： user:view 失败抛出异常
        subject().checkPermissions("user:view");
    }

    @Test
    public void testWildcardPermission1() {
        login("classpath:shiro-permission.ini", "li", "123");

        //检查有权限：user:update,delete
        subject().checkPermissions("system:user:update", "system:user:delete");
        subject().checkPermissions("system:user:update,delete");
    }

    @Test
    public void testWildcardPermission2() {
        login("classpath:shiro-permission.ini", "li", "123");

        subject().checkPermissions("system:user:create,delete,update,view");
        subject().checkPermissions("system:user:*");
        subject().checkPermissions("system:user");
    }

    @Test
    public void testWildcardPermission3() {
        login("classpath:shiro-permission.ini", "li", "123");

        subject().checkPermissions("user:view");
        subject().checkPermissions("system:user:view");
    }

    @Test
    public void testWildcardPermission4() {
        login("classpath:shiro-permission.ini", "li", "123");

        subject().checkPermissions("user:view:1");
        subject().checkPermissions("user:update:1", "user:delete:1");
        subject().checkPermissions("user:create:1", "user:update:1", "user:delete:1", "user:view:1");
        subject().checkPermissions("user:auth:1", "user:auth:2");
    }

    @Test
    public void testWildcardPermission5() {
        login("classpath:shiro-permission.ini", "li", "123");

        subject().checkPermissions("organization");
        subject().checkPermissions("organization:view");
        subject().checkPermissions("organization:view:1");
    }

    @Test
    public void testWildcardPermission6() {
        login("classpath:shiro-permission.ini", "li", "123");

        subject().checkPermission("menu:view:1");
        subject().checkPermission(new WildcardPermission("menu:view:1"));

    }
}
