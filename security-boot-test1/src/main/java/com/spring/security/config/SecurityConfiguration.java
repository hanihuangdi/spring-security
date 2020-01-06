package com.spring.security.config;

import com.spring.security.service.UserService;
import com.spring.security.service.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfiguration  extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;

    /*
      * @Description:加密
      * @Author:hcf
      * @Date: 2020/1/2 21:22
      * @param:
      * @return:
     */
    @Bean
    public BCryptPasswordEncoder getbc(){
        return  new BCryptPasswordEncoder();
    }
    //认证用户的来源

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      /*  auth.inMemoryAuthentication()//内存认证
                .withUser("user")
                .password("{noop}123")
                .roles("USER");*/
        auth.userDetailsService(userService).passwordEncoder(getbc());

    }

    //配置security的相关信息
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //释放静态资源，指定拦截路径，指定自定义页面，指定退出配置，csrf配置
        http.authorizeRequests()
                .antMatchers("/login.jsp","/img/**","/plugins/**","/failer.jsp").permitAll()//permitAll表示不拦截这些
                .antMatchers("/**").hasAnyRole("USER")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login.jsp")
                .loginProcessingUrl("/login")
                .successForwardUrl("/index.jsp")
                .failureForwardUrl("/failer.jsp")
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login.jsp")
                .invalidateHttpSession(true)
                .permitAll()
                .and()
                .csrf()
                .disable();
    }
}
