package spring.security.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.leyou.common.utils.JwtUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import spring.security.auth.configpropertis.RsaKeyProperties;
import spring.security.auth.domian.SysRole;
import spring.security.auth.domian.SysUser;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
/*
 * @Description:认证过滤器
 * @Author:hcf
 * @Date: 2020/1/3 15:38
 * @param:
 * @return:
 */
public class TokenLoginFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager; //角色资源管理对象
    private RsaKeyProperties prop;//获取公钥私钥


    public TokenLoginFilter(AuthenticationManager authenticationManager, RsaKeyProperties prop) {
        this.authenticationManager = authenticationManager;
        this.prop = prop;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        ObjectMapper mapper = new ObjectMapper();
        try {

            SysUser sysUser = mapper.readValue(request.getInputStream(), SysUser.class);
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(sysUser.getUsername(), sysUser.getPassword());
            return authenticationManager.authenticate(authRequest);
        } catch (IOException e) {
            try {
            response.setContentType("application/json;charset=utf-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                HashMap resultMap = new HashMap();
                resultMap.put("code",HttpServletResponse.SC_UNAUTHORIZED);
                resultMap.put("msg","用户名或密码错误！");
                response.getWriter().write(mapper.writeValueAsString(resultMap));
            } catch (IOException ex) {
                ex.printStackTrace();
            }
            throw  new RuntimeException(e);
        }


    }
    /*
      * @Description:认证成功后的操作
      * @Author:hcf
      * @Date: 2020/1/3 15:17
      * @param:
      * @return:
     */
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        ObjectMapper mapper = new ObjectMapper();
        try {
            SysUser sysUser = new SysUser();
           sysUser.setUsername(authResult.getName());
           sysUser.setRoles((List<SysRole>) authResult.getAuthorities());
            String token = JwtUtils.generateToken(sysUser, prop.getPrivateKey(), 60 * 24);
            response.setHeader("Authorization","Bearer "+token);
                response.setContentType("application/json;charset=utf-8");
                response.setStatus(HttpServletResponse.SC_OK);
                HashMap resultMap = new HashMap();
                resultMap.put("code",HttpServletResponse.SC_OK);
                resultMap.put("msg","认证通过！");
                response.getWriter().write(mapper.writeValueAsString(resultMap));

            } catch (IOException ex) {
                ex.printStackTrace();
            } catch (Exception e) {
            e.printStackTrace();
        }
        }

    }
