package com.wyrhero.shirodemo.chapter3.authorizer;

import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

public class RoleTest extends BaseTest {

    @Test
    public void testHasRole(){
        login("classpath:shiro-role.ini","zhang","123");
        //判断拥有角色： role1
        Assert.assertTrue(subject().hasRole("role1"));
        //判断拥有角色： role1 and role2
        Assert.assertTrue(subject().hasAllRoles(Arrays.asList("role1","role2")));
        //判断拥有角色： role1 and role2 and !role3
        boolean[] result = subject().hasRoles(Arrays.asList("role1","role2","role3"));
        Assert.assertTrue(result[0]);
        Assert.assertTrue(result[1]);
        Assert.assertFalse(result[2]);

    }
}
