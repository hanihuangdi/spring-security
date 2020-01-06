package spring.security.auth.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/product")
public class ProductController {
   /* @Secured("ROLE_ADMIN")*/
    @RequestMapping
    public String findAll(){
        return "查询成功";
    }
}
