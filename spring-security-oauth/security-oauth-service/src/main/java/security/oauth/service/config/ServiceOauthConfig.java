package security.oauth.service.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import security.oauth.service.service.UserService;

import javax.sql.DataSource;

@Configuration
@EnableAuthorizationServer
public class ServiceOauthConfig extends AuthorizationServerConfigurerAdapter {
    //数据库连接对象
    @Autowired
    private DataSource dataSource;
    //认证业务对象
    @Autowired
    private UserService userService;
    //授权模式专用对象
    @Autowired
    private AuthenticationManager authenticationManager;
    //客户端信息来源
    @Bean
    public JdbcClientDetailsService jdbcClientDetailsService(){
        return new JdbcClientDetailsService(dataSource);
    }
    //token保存策略
    @Bean
    public TokenStore tokenStore(){
        return new JdbcTokenStore(dataSource);
    }
    //授权信息保存策略
    @Bean
    public ApprovalStore approvalStore(){
        return new JdbcApprovalStore(dataSource);
    }

    //授权模式数据来源
    @Bean
    public AuthorizationCodeServices authorizationCodeServices(){
        return new JdbcAuthorizationCodeServices(dataSource);
    }

    //检查token的策略
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
       security.allowFormAuthenticationForClients();//允许地址栏的请求
        security.checkTokenAccess("idAuthenticated()");

    }
    //指定客户端数据来源
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(jdbcClientDetailsService());
    }
    //oauth2的主配置信息
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints
                    .approvalStore(approvalStore())
                    .authenticationManager(authenticationManager)
                    .authorizationCodeServices(authorizationCodeServices())
                    .tokenStore(tokenStore());
    }
}
