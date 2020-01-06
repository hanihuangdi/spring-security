package spring.security.auth.config;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import spring.security.auth.configpropertis.RsaKeyProperties;
import spring.security.auth.filter.JwtVerifyFilter;
import spring.security.auth.filter.TokenLoginFilter;
import spring.security.auth.service.UserService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;
    @Autowired
    RsaKeyProperties prop;
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
        http.csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/product").hasAnyRole("USER")
                .anyRequest()
                .authenticated()
                .and()
                //.addFilter(new TokenLoginFilter(super.authenticationManager(),prop))
               // .addFilter(new JwtVerifyFilter(super.authenticationManager(),prop))
                .formLogin()
                .loginProcessingUrl("/login")
                .permitAll()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);


    }
}
