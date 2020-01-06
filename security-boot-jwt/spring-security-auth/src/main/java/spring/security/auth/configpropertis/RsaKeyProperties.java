package spring.security.auth.configpropertis;

import com.leyou.common.utils.RsaUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.security.PrivateKey;
import java.security.PublicKey;
@Component
public class RsaKeyProperties {
    @Value("${rsa.pubKeyFile}")
    private String pubKeyFile;
    @Value("${rsa.priKeyFile}")
    private  String priKeyFile;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    @PostConstruct
    public void getPubkey() throws Exception {
        this.publicKey = RsaUtils.getPublicKey(pubKeyFile);
    }
    @PostConstruct
    public void getPriKey() throws Exception {
        this.privateKey = RsaUtils.getPrivateKey(priKeyFile);
    }
    public String getPubKeyFile() {
        return pubKeyFile;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void setPubKeyFile(String pubKeyFile) {
        this.pubKeyFile = pubKeyFile;
    }

    public String getPriKeyFile() {
        return priKeyFile;
    }

    public void setPriKeyFile(String priKeyFile) {
        this.priKeyFile = priKeyFile;
    }
}
