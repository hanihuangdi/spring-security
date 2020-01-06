package spring.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import spring.security.auth.configpropertis.RsaKeyProperties;
import tk.mybatis.spring.annotation.MapperScan;

@SpringBootApplication
@MapperScan("spring.security.auth.dao")
public class AuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class,args);
    }
}
