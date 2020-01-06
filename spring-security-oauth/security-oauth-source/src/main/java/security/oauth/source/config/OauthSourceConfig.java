package security.oauth.source.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;
/*
  * @Description:资源服务管理
  * @Author:hcf
  * @Date: 2020/1/5 12:10
  * @param:
  * @return:
 */
@Configuration
@EnableResourceServer
public class OauthSourceConfig extends ResourceServerConfigurerAdapter {
    @Autowired
   private DataSource ds;
    /*
     * @Description:指定token的持久化策略
     * @Author:hcf
     * @Date: 2020/1/5 11:54
     * @param: []
     * @return: org.springframework.security.oauth2.provider.token.TokenStore
     */
    @Bean
    public TokenStore jdbcTokenStore(){

        return new JdbcTokenStore(ds);
    }
    /*
     * @Description:指定当前资源的id和存储方案
     * @Author:hcf
     * @Date: 2020/1/5 11:58
     * @param: [resources]
     * @return: void
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
       resources.resourceId("product-api").tokenStore(jdbcTokenStore());

    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(HttpMethod.GET,"/**").access("#oauth2.hasScope('read')")
                .antMatchers(HttpMethod.POST,"/**").access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.PATCH,"/**").access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.PUT,"/**").access("#oauth2.hasScope('write')")
                .antMatchers(HttpMethod.DELETE,"/**").access("#oauth2.hasScope('write')")
                .and()
                .headers().addHeaderWriter((request,response)->{
              response.addHeader("Access-Control-Allow-Origin","*");
            if(request.getMethod().equals("OPTIONS")){//如果是跨域请求，则传递头信息
                response.setHeader("Access-Control-Allow-Methods",request.getHeader("Access-Control-Request-Method"));
                response.setHeader("Access-Control-Allow-Headers",request.getHeader("Access-Control-Request-Headers"));
            }

        });

    }
}
