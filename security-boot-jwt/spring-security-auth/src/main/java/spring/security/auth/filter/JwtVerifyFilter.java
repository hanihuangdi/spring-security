package spring.security.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.leyou.common.domain.Payload;
import com.leyou.common.utils.JwtUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import spring.security.auth.configpropertis.RsaKeyProperties;
import spring.security.auth.domian.SysUser;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;

/*
  * @Description:验证过滤器
  * @Author:hcf
  * @Date: 2020/1/3 15:38
  * @param:
  * @return:
 */
public class JwtVerifyFilter extends BasicAuthenticationFilter {
    private RsaKeyProperties prop;
    public JwtVerifyFilter(AuthenticationManager authenticationManager,RsaKeyProperties prop) {
        super(authenticationManager);
        this.prop = prop;
    }

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String header = request.getHeader("Authorization");
        if (header == null ||!header.startsWith("Bearer ")) {
            //没有携带的错误的token则请登录
            response.setContentType("application/json;charset=utf-8");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            HashMap resultMap = new HashMap();
            resultMap.put("code",HttpServletResponse.SC_FORBIDDEN);
            resultMap.put("msg","请登录！");
            response.getWriter().write(new ObjectMapper().writeValueAsString(resultMap));

            chain.doFilter(request, response);
        } else {
            //携带了正确格式的token
            String token = header.replace("Bearer ", "");

            try {
                //验证token是否正确,获取载荷
                Payload<SysUser> payload = JwtUtils.getInfoFromToken(token, prop.getPublicKey(), SysUser.class);
                SysUser userInfo = payload.getUserInfo();
                if(userInfo!=null){
                Authentication authentication = new UsernamePasswordAuthenticationToken(userInfo.getUsername(),null,userInfo.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
                chain.doFilter(request, response);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
    }
}
