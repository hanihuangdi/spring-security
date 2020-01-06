package security.oauth.source;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("security.oauth.source.dao")
public class SourceApplication {
    public static void main(String[] args) {
        SpringApplication.run(SourceApplication.class,args);
    }
}
