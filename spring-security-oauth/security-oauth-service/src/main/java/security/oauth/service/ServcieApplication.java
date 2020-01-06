package security.oauth.service;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("security.oauth.service.dao")
public class ServcieApplication {
    public static void main(String[] args) {
        SpringApplication.run(ServcieApplication.class,args);
    }
}
