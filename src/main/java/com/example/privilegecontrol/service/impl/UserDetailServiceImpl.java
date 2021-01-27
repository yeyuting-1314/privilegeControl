package com.example.privilegecontrol.service.impl;

import com.example.privilegecontrol.domain.Admin;
import com.example.privilegecontrol.domain.Employee;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @author yeyuting
 * @create 2021/1/21
 */
@Service
/*
* 用户在登录时 Spring Security 会通过 UserDetailsService.loadUserByUsername() 方法获取登录的用户的详细信息，
* 然后会将用户的数据封装进 UserDetails 对象中，因此这里需要实现UserDetailsService接口，并重写loadUserByUsername方法
* */
public class UserDetailServiceImpl implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //角色和权限共用GrantedAuthority接口，后面采集到的角色信息将存储到grantedAuthorities集合中
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        //生成环境是查询数据库获取username的角色用于后续权限判断（如：张三 admin)
        //这里暂时先不做数据库操作，给定假数据，我们后面再加入数据库
        if (username.equals("employee")) {
            Employee employee = new Employee();
            employee.setUsername("employee");
            employee.setPassword("123456");
            //对employ对象赋予ROLE_EMPLOYEE角色，存储到grantedAuthority中
            GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_EMPLOYEE");
            //将已经被赋予角色的grantedAuthority存储到grantedAuthorities集合中
            grantedAuthorities.add(grantedAuthority);
            //创建一个用户，用于判断权限，请注意此用户名和方法参数中的username一致；BCryptPasswordEncoder是用来演示加密使用。
            //这里主要是实现用户名和密码的核对，如果信息都正确才给开这个权限，这是一种安全策略
            return new User(employee.getUsername(), new BCryptPasswordEncoder().encode(employee.getPassword()), grantedAuthorities);
        }
        if (username.equals("admin")) {
            Admin admin = new Admin();
            admin.setUsername("admin");
            admin.setPassword("123456");
            GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
            grantedAuthorities.add(grantedAuthority);
            return new User(admin.getUsername(), new BCryptPasswordEncoder().encode(admin.getPassword()), grantedAuthorities);
        }
        else {
            return null;
        }


    }
}
