package com.leyou.common.utils;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.PublicKey;

import static org.junit.Assert.*;


public class RsaUtilsTest {
    private  String  privateFile="E:\\demo\\tools\\newRSA\\rsa.pri";
    private  String  publicFile="E:\\demo\\tools\\newRSA\\rsa.pub";


    @Test
    public void getPublicKey() throws Exception {
        System.out.println(RsaUtils.getPublicKey(publicFile));
    }

    @Test
    public void getPrivateKey() throws Exception {
        System.out.println(RsaUtils.getPrivateKey(privateFile));
    }

    @Test
    public void testGetPublicKey() {
    }

    @Test
    public void testGetPrivateKey() {
    }

    @Test
    public void generateKey() throws Exception {
        RsaUtils.generateKey(publicFile,privateFile,"2048");
    }

}
