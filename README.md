## spring-security

### 1.快速入门

导入依赖

```
<dependencies> 
	<dependency> 
        <groupId>org.springframework.security</groupId> 
        <artifactId>spring-security-web</artifactId> 
        <version>5.0.1.RELEASE</version> 
	</dependency> 
	<dependency> 
        <groupId>org.springframework.security</groupId> 
        <artifactId>spring-security-config</artifactId> 
        <version>5.0.1.RELEASE</version> 
	</dependency> 
</dependencies>
```

web.xml

```xml
<?xml version="1.0"?>
<context-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>classpath:spring-security.xml</param-value>
</context-param>
<listener>
    <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
</listener>
<filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>
<filter-mapping>
    <filter-name>springSecurityFilterChain</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

spring-security

```xml
<?xml version="1.0" encoding="utf-8"?>
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:security="http://www.springframework.org/schema/security" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/security http://www.springframework.org/schema/security/spring-security.xsd">
    <security:http auto-config="true" use-expressions="false">
        <!-- intercept-url定义一个过滤规则 pattern表示对哪些url进行权限控制，ccess属性表示在请求对应 的URL时需要什么权限， 默认配置时它应该是一个以逗号分隔的角色列表，请求的用户只需拥有其中的一个角色就能成功访问对应 的URL -->
        <security:intercept-url pattern="/**" access="ROLE_USER" />
        <!-- auto-config配置后，不需要在配置下面信息 <security:form-login /> 定义登录表单信息 <security:http-basic /> <security:logout /> -->
    </security:http>
    <security:authentication-manager>
        <security:authentication-provider>
            <security:user-service>
                <security:user name="user" password="{noop}user" authorities="ROLE_USER" />
                <security:user name="admin" password="{noop}admin" authorities="ROLE_ADMIN" />
            </security:user-service>
        </security:authentication-provider>
    </security:authentication-manager>
</beans>
```

自定义页面的spring security

```xml
<?xml version="1.0" encoding="utf-8"?>
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:security="http://www.springframework.org/schema/security" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/security http://www.springframework.org/schema/security/spring-security.xsd">
    <!-- 配置不过滤的资源（静态资源及登录相关） -->
    <security:http security="none" pattern="/login.html" />
    <security:http security="none" pattern="/failer.html" />
    <security:http auto-config="true" use-expressions="false">
        <!-- 配置资料连接，表示任意路径都需要ROLE_USER权限 -->
    <security:intercept-url pattern="/**" access="ROLE_USER" />
        <!-- 自定义登陆页面，
            login-page 自定义登陆页面 
            authentication-failure-url 用户权限校验失败之 后才会跳转到这个页面，如果数据库中没有这个用户则不会跳转到这个页面。 
            default-target-url 登陆成功后跳转的页面。 
            注：登陆页面用户名固定 username，密码 password，
            action:login -->
        <security:form-login login-page="/login.html" login-processing-url="/login" username-parameter="username" password-parameter="password" authentication-failure-url="/failer.html" default-target-url="/success.html" />
        <!-- 登出， invalidate-session 是否删除session logout-url：登出处理链接 logout-success- url：登出成功页面注：登出操作 只需要链接到 logout即可登出当前用户 -->
        <security:logout invalidate-session="true" logout-url="/logout" logout-success-url="/login.jsp" />
        <!-- 关闭CSRF,默认是开启的 -->
        <security:csrf disabled="true" />
    </security:http>
    <security:authentication-manager>
        <security:authentication-provider>
            <security:user-service>
                <security:user name="user" password="{noop}user" authorities="ROLE_USER" />
                <security:user name="admin" password="{noop}admin" authorities="ROLE_ADMIN" />
            </security:user-service>
        </security:authentication-provider>
    </security:authentication-manager>
</beans>
```

### **2.数据库认证** 

userdetils

```java
public interface UserDetails extends Serializable {
    Collection <? extends GrantedAuthority > getAuthorities();
    String getPassword();
    String getUsername();
    boolean isAccountNonExpired();
    boolean isAccountNonLocked();
    boolean isCredentialsNonExpired();
    boolean isEnabled();
}//security提供
```

user

```java
public class User implements UserDetails, CredentialsContainer {
    private String password;
    private final String username;
    private final Set < GrantedAuthority > authorities;
    private final boolean accountNonExpired; //帐户是否过期 
    private final boolean accountNonLocked; //帐户是否锁定 
    private final boolean credentialsNonExpired; //认证是否过期 
    private final boolean enabled; //帐户是否可用 ｝
    
   UserDetails是一个接口，我们可以认为UserDetails作用是于封装当前进行认证的用户信息，但由于其是一个
接口，所以我们可以对其进行实现，也可以使用Spring Security提供的一个UserDetails的实现类User来完成
操作
```

userdetilsService

```java
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}//security提供
```

spring-security

```xml
<security:authentication-manager>
    <security:authentication-provider user-service-ref="userServiceImpl">
        <!-- 配置加密的方式 <security:password-encoder ref="passwordEncoder"/> -->
    </security:authentication-provider>
</security:authentication-manager>
```

使用加密方式，在设置密码时要加密才能够匹配,没使用加密方式在service设置密码时要添加"{noop}"

参考https://blog.csdn.net/u012211603/article/details/81659907

service

```
public interface IUserService extends UserDetailsService{ 

}
UserDetailService是用户权限管理的一个规范，IUserService是客户的权限管理规范
```

```java
@Service("userService")
@Transactional 
public class UserServiceImpl implements IUserService {
    @Autowired 
    private IUserDao userDao;
    @Override 
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //获取用户信息
        UserInfo userInfo = userDao.findByUsername(username);
        //获取用户的角色信息
        List < Role > roles = userInfo.getRoles();
        //获取角色的权限信息
        List < SimpleGrantedAuthority > authoritys = getAuthority(roles);
        //封装信息到User
        User user = new User(userInfo.getUsername(), "{noop}" + userInfo.getPassword(), userInfo.getStatus() == 0 ? false : true, true, true, true, authoritys);
        return user;
    }
    private List < SimpleGrantedAuthority > getAuthority(List < Role > roles) {
        List < SimpleGrantedAuthority > authoritys = new ArrayList();
        for (Role role: roles) {
            authoritys.add(new SimpleGrantedAuthority(role.getRoleName()));
        }
        return authoritys;
    }
}
```

### **3.服务器端方法级权限控制**

```
Spring Security在方法的权限控制上
支持三种类型的注解：

    JSR-250注解、
    @Secured注解、
    支持表达式的注解，
    
这三种注解默认都是没有启用的，需要
单独通过global-method-security元素的对应属性进行启用
```

配置文件

```
<security:global-method-security jsr250-annotations="enabled"/>
<security:global-method-security secured-annotations="enabled"/>
<security:global-method-security pre-post-annotations="disabled"/>
```

注解开启

```
@EnableGlobalMethodSecurity ：Spring Security默认是禁用注解的，
注解开发
需要在继承WebSecurityConfigurerAdapter的类上加@EnableGlobalMethodSecurity注解，并在该类中将
AuthenticationManager定义为Bean。
```

#### JSR-250注解

```
@RolesAllowed表示访问对应方法时所应该具有的角色
示例： @RolesAllowed({"USER", "ADMIN"}) 该方法只要具有"USER", "ADMIN"任意一种权限就可以访问。这里可以省 略前缀ROLE_，实际的权限可能是ROLE_ADMIN

@PermitAll表示允许所有的角色进行访问，也就是说不进行权限控制

@DenyAll是和PermitAll相反的，表示无论什么角色都不能访问
```

#### 注解表达式

@PreAuthorize 在方法调用之前,基于表达式的计算结果来限制对方法的访问

```
示例： @PreAuthorize("#userId == authentication.principal.userId or hasAuthority(‘ADMIN’)") void changePassword(@P("userId") long userId ){ } 这里表示在changePassword方法执行之前，判断方法参数userId的值是否等于principal中保存的当前用户的 userId，或者当前用户是否具有ROLE_ADMIN权限，两种符合其一，就可以访问该方法。
```

@PostAuthorize 允许方法调用,但是如果表达式计算结果为false,将抛出一个安全性异常

```
示例： 
@PostAuthorize 
User getUser("returnObject.userId == authentication.principal.userId or hasPermission(returnObject, 'ADMIN')");
```

@PostFilter 允许方法调用,但必须按照表达式来过滤方法的结果 

@PreFilter 允许方法调用,但必须在进入方法之前过滤输入值 

#### **@Secured**

```
@Secured注解标注的方法进行权限控制的支持，其值默认为disabled。
示例： 
@Secured("IS_AUTHENTICATED_ANONYMOUSLY") 
public Account readAccount(Long id);
@Secured("ROLE_TELLER")
```

### **4.页面端标签控制权限**

在jsp页面中我们可以使用spring security提供的权限标签来进行权限控制 

引入依赖

```
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-taglibs</artifactId>
    <version>version</version>
</dependency>
```

页面导入

```
<%@taglib uri="http://www.springframework.org/security/tags" prefix="security"%>
```

**常用标签**

 **authentication** 

```
<security:authentication property="" htmlEscape="" scope="" var=""/>
```

property： 只允许指定Authentication所拥有的属性，可以进行属性的级联获取，如“principle.username”，
不允许直接通过方法进行调用

htmlEscape：表示是否需要将html进行转义。默认为true。

scope：与var属性一起使用，用于指定存放获取的结果的属性名的作用范围，默认我pageContext。Jsp中拥
有的作用范围都进行进行指定

var： 用于指定一个属性名，这样当获取到了authentication的相关信息后会将其以var指定的属性名进行存
放，默认是存放在pageConext中

**authorize** 

authorize是用来判断普通权限的，通过判断用户是否具有对应的权限而控制其所包含内容的显示 

```
<security:authorize access="" method="" url="" var=""></security:authorize>
```

access： 需要使用表达式来判断权限，当表达式的返回结果为true时表示拥有对应的权限
method：method属性是配合url属性一起使用的，表示用户应当具有指定url指定method访问的权限，
method的默认值为GET，可选值为http请求的7种方法
url：url表示如果用户拥有访问指定url的权限即表示可以显示authorize标签包含的内容
var：用于指定将权限鉴定的结果存放在pageContext的哪个属性中

 **accesscontrollist** 

accesscontrollist标签是用于鉴定ACL权限的。其一共定义了三个属性：hasPermission、domainObject和var，
其中前两个是必须指定的

```
<security:accesscontrollist hasPermission="" domainObject="" var=""></security:accesscontrollist>
```

hasPermission：hasPermission属性用于指定以逗号分隔的权限列表
domainObject：domainObject用于指定对应的域对象
var：var则是用以将鉴定的结果以指定的属性名存入pageContext中，以供同一页面的其它地方使用

### 5.remember-me记住我

通过分析验证通过后的源码，知道要开启记住我功能，要求：提交数据的name="remember-me",value="{yes,1,true,on}"

在配置中开启过滤器

```
<security:remember-me key="elim" user-service-ref="userService token-validity-seconds="60""/>
```

持久化token信息

![image-20200101214942644](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200101214942644.png)

根据官方文档提供的信息建立表，配置文件设置

```
<security:remember-me
	data-source-ref="dataSource"
	token-validity-seconds="60"
	rememberme-parameter="remember-me"/>
```

### 6.异常处理

1.配置文件配置

```
<security:access-denied-handler error-page="/403.jsp"/>
```

2.web.xml中配置

```
<web-app>
	<error-code>403</error-code>
	<error-page>/403.jsp</error-page>
</web-app>
```

3.自定义异常处理类

```java
方式一
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        HashMap<String, String> result = new HashMap<>();
        result.put("code", "1");
        result.put("msg", "无权限访问");
       ObjectMapper objectMapper = new ObjectMapper();
        response.getWriter().append(objectMapper.writeValueAsString(result));
    }
}
方式二
@ControllerAdvice
public class HandlerControllerAdvice{
    
    @ExceptionHandler(AccessDeniedExcption.class)
    public String handlerException(){
        return "/403.jsp";
    }
    
}
```



### 7.原理分析

**1.为何spring-security加载配置文件需要在监听器中而不是和dispacterServlet一起启动？**

servlet中启动用户可以直接与controlller层交互访问到其中的数据，而监听器中启动用户无法直接访问到其中的数据的，spring-security中的数据我们不希望让外界访问到，所以需要在监听器中加载。

外界可以访问子容器不能访问父容器，要调用父容器的资源可以通过子容器调用。



**2.org.springframework.security.web.csrf.CsrfFilter**

spring-security是由多个过滤组成的，其中csrf.CsrfFilter过滤器是用来阻止跨域伪造请求的。

csrf跨域伪造请求，默认是开启。可以通过配置文件修改``<security:csrf disabled="true"/>``

在自定义页面中如果配置文件有开启禁止跨域伪造请求，则需要在 提交数据提供一个动态的token验证，不提供则会报错。   凡是对数据库造成修改的请求都会被csrf拦截器拦截，下面的为直接放行的请求方式

![image-20200101171914019](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200101171914019.png)

页面定义提交token数据的标签

```
<%@taglib uri="http://www.springframework.org/security/tags" prefix="security"%>
<security:csrfInput/>
```

开启CsrfFilter要求退出请求使用POST

**3.spring-security过滤器链的加载原理**

通过分析源码启动，可以观察到这些到滤器链是由SecurityFilterChain这个过滤器完成封装的。

![image-20200101141941909](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200101141941909.png)

![image-20200101142014628](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200101142014628.png)

点进去invoke中可以看出此方法的功能是执行这些过滤器让其生效，所以这边就不用再看

initDelegate可以看出应该是初始化的，从这边进去分析是怎么执行的。

![image-20200101142314589](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200101142314589.png)

可以看到，获取标签中的名称getTargetBeanName(),是用来通过bean的id获取对象的，所以配置文件中的过滤器名称必须是springSecurityFilterChain。

从这边看到返回的对象是delegate类型为FilterChainProxy,那么就看下是不是在这里面进行的封装。

![image-20200101142738619](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200101142738619.png)

进入FilterChainProxy中发现filters 在启动时就加入了15个过滤器。在进一步看下getFilters中做了什么。

![image-20200101142931029](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200101142931029.png)

可以看到这边过滤器链中的过滤器是由SecurityFilterChain封装的。通过SecurityFilterChain的实现类将15过滤器初始化到容器中。

**4.开启csrf拦截时的退出请求，退出的拦截器，要求请求为POST请求否则会报错**

### 8.整合springboot

#### security默认页面案例

创建springboot项目，引入依赖

```jsp
 <groupId>spring-security-boot</groupId>
    <artifactId>security-boot-test1</artifactId>
    <version>1.0-SNAPSHOT</version>
    <packaging>war</packaging><!--快速的转为web项目-->

<parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-parent</artifactId>
        <version>2.0.7.RELEASE</version>
    </parent>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
   
        </dependency>
```

创建配置文件application.yml

```yml
server:
  port: 8080
```

controller类测试

```java
@Controller
@RequestMapping("/product")
public class ProductController {

    @RequestMapping
    @ResponsBody
    public String findAll(){
        return "success";
    }
}

```

测试启动类

```java
@SpringBootApplication
public class SecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class,args);
    }
}
```

整合jsp,添加依赖

```jsp
 <!--整合jsp-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-tomcat</artifactId>
        </dependency>
        <dependency>
            <groupId>org.apache.tomcat.embed</groupId>
            <artifactId>tomcat-embed-jasper</artifactId>
        </dependency>
        <!--整合security-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
```

启动时使用mvn命令 spring-boot:run，测试security的默认登录页面。

#### security自定义配置

创建配置类

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration  extends WebSecurityConfigurerAdapter {
    //认证用户的来源


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()//内存认证
                .withUser("user")
                .password("{noop}123")
                .roles("USER");
    }

    //配置security的相关信息
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //释放静态资源，指定拦截路径，指定自定义页面，指定退出配置，csrf配置
        http.authorizeRequests()
                .antMatchers("/login.jsp","/img/**","/plugins/**","/failer.jsp").permitAll()//permitAll表示不拦截这些
                .antMatchers("/**").hasAnyRole("USER")
                .anyRequest()
                .authenticated()	//anyRequest,authenticated表示其他的资源需要认证后访问
                .and()
                .formLogin()
                .loginPage("/login.jsp")
                .loginProcessingUrl("/login")
                .successForwardUrl("/index.jsp")
                .failureForwardUrl("/failer.jsp")
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login.jsp")
                .invalidateHttpSession(true)
                .permitAll()
                .and()
                .csrf()
                .disable();
    }
}

```

配置文件配置静态文件解析

```yml
server:
  port: 8080
spring:
  mvc:
    view:
      prefix: /pages/
      suffix: .jsp
```

启动测试

#### security数据库认证

引入依赖

```jsp
  <!--myslq-->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>5.1.47</version>
        </dependency>
        <!--通用mapper-->
        <dependency>
            <groupId>tk.mybatis</groupId>
            <artifactId>mapper-spring-boot-starter</artifactId>
            <version>2.1.5</version>
        </dependency>
```

配置数据库连接

```yml
server:
  port: 8080
spring:
  mvc:
    view:
      prefix: /pages/
      suffix: .jsp
  datasource:
    driver-class-name: com.mysql.jdbc.Driver
    url: jdbc:mysql:///security_authority
    data-username: root
    data-password: root
mybatis:
  type-aliases-package: com.spring.security.domian
  configuration:
    map-underscore-to-camel-case: true
logging:
  level:
    com.spring.security: debug
```

开启mapper扫描

```java
@SpringBootApplication
@MapperScan("com.spring.security.dao")
public class SecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class,args);
    }
}

```

根据数据库创建实体类 user,role

```java
public class SysUser implements UserDetails {
    private Integer id;
    private String username;
    private  String password;
    private  Integer status;
    private List<SysRole> roles;
   //以下省略get,set和实现方法
    }
```

```java
public class SysRole implements GrantedAuthority {
    private  Integer id;
    private  String roleName;
    private  String roleDesc;
//以下省略get,set和实现方法
    }
```

mapper创建以及完成查询

```java
public interface RoleMapper extends Mapper<SysRole> {
    @Select("SELECT r.* FROM sys_role r INNER  JOIN  sys_user_role ur ON r.id=ur.roleid where userId = #{userId} ")
    List<SysRole> findByUid(Integer userId);
}

```

```java
public interface UserMapper  extends Mapper<SysUser> {

    @Select("select * from sys_user where username = #{username}")
    @Results({
            @Result(id=true,column = "id",property = "id"),
            @Result(column = "id",property = "roles",javaType = List.class,many=@Many(select = "com.spring.security.dao.RoleMapper.findByUid")),

    })
    SysUser findByName(String username);
}
```

修改配置类信息

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfiguration  extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;  //注入认证方法

    /*
      * @Description:加密方法
      * @Author:hcf
      * @Date: 2020/1/2 21:22
      * @param:
      * @return:
     */
    @Bean
    public BCryptPasswordEncoder getbc(){
        return  new BCryptPasswordEncoder();
    }
    //认证用户的来源

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      /*  auth.inMemoryAuthentication()//内存认证
                .withUser("user")
                .password("{noop}123")
                .roles("USER");*/
        auth.userDetailsService(userService).passwordEncoder(getbc());

    }
```

权限异常处理

```java
@ControllerAdvice
public class ExceptionAdvice {
    @ExceptionHandler(RuntimeException.class)
    public String ExceptionHandler(RuntimeException e){
        if(e instanceof AccessDeniedException){
            return "redirect:/403.jsp";
        }
        return "redirect:/500.jsp";
    }
}
```

### 9.分布式

1.分布式项目一般采用AJAX提交请求所以需要重写，security中UsernamePasswordAuthenticationFilter的attemptAuthentication方法。

2.认证成功后需要通过JWT和RSA进行加密处理返回数据，所以要对AbstractAuthenticationProcessingFilter中的successfulAuthentication方法进行重写

3.security使用BasicAuthenticationFilter过滤器中的doFilter进行验证是否登录，由于我们对token进行了加密处理，所以也需要对验证的方法进行重写



**分布式登录信息就无法再存储在sesion中所以需要采用无状态登录，使用JWT+RSA完成**



TokenLoginFilter

```java
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
```

JwtVerityFile

```java
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
```

securityConfiguration

```java
package spring.security.auth.config;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import spring.security.auth.configpropertis.RsaKeyProperties;
import spring.security.auth.filter.JwtVerifyFilter;
import spring.security.auth.filter.TokenLoginFilter;
import spring.security.auth.service.UserService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;
    @Autowired
    RsaKeyProperties prop;
    /*
      * @Description:加密
      * @Author:hcf
      * @Date: 2020/1/2 21:22
      * @param:
      * @return:
     */
    @Bean
    public BCryptPasswordEncoder getbc(){
        return  new BCryptPasswordEncoder();
    }
    //认证用户的来源

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      /*  auth.inMemoryAuthentication()//内存认证
                .withUser("user")
                .password("{noop}123")
                .roles("USER");*/
        auth.userDetailsService(userService).passwordEncoder(getbc());

    }

    //配置security的相关信息
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //释放静态资源，指定拦截路径，指定自定义页面，指定退出配置，csrf配置
        http.csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/product").hasAnyRole("USER")
                .anyRequest()
                .authenticated()
                .and()
                .addFilter(new TokenLoginFilter(super.authenticationManager(),prop))
                .addFilter(new JwtVerifyFilter(super.authenticationManager(),prop))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);


    }
}

```



### 10.oauth2

实现一个客户端通过授权直接访问另外一个客户端的接口。

A客户端访问B客户端的接口

- 客户需要有A,B两个客户端的权限
- B客户端需要存储A客户端的信息
- A客户端发送请求向用户申请授权，同意之后，返回授权码给A
- A客户端通过授权码向B客户端发送资源权限请求，B返回一个token给A
- A之后拿着token就可以直接访问B的接口

类似一个软件需要使用微信朋友圈的功能，首先需要登录微信获得授权，之后拿着授权码访问微信资源权限接口，返回一个token，根据token可以得到能够访问的资源权限，则可以进行下一步操作

官方sql语句https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/test/resources/schema.sql

认证模式分为4种模式

- 授权码模式（重点）
- 简化模式
- 密码模式
- 客户端模式

**入门案例**

**创建父级工程**

引入springboot,springcloud依赖

**资源工程创建**

引入依赖

```jsp
 <dependencies>
        <dependency>
            <groupId>spring-security-oauth2</groupId>
            <artifactId>security-oauth-service</artifactId>
            <version>1.0-SNAPSHOT</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
 
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-oauth2</artifactId>
            <version>2.2.0.RELEASE</version>
        </dependency>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>5.1.47</version>
        </dependency>
        <dependency>
            <groupId>org.mybatis.spring.boot</groupId>
            <artifactId>mybatis-spring-boot-starter</artifactId>
            <version>2.1.0</version>
        </dependency>
    </dependencies>
```

yml文件配置

```yml
server:
  port: 9001
spring:
  datasource:
    driver-class-name: com.mysql.jdbc.Driver
    url: jdbc:mysql:///security_authority
    data-username: root
    data-password: root
  main:
    allow-bean-definition-overriding: true  #允许覆盖IOC容器中的bean
mybatis:
  type-aliases-package: security.oauth.source.domain
  configuration:
    map-underscore-to-camel-case: true
logging:
  level:
    security.oauth.source: debug
```

创建配置类,将资源交给oauth2管理

```java
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

```

**服务工程创建**

ServiceSecurityConfig

```java
@Configuration
@EnableWebSecurity
public class ServiceSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(userService).passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .formLogin()
                    .loginProcessingUrl("/login")
                    .permitAll()
                    .and()
                    .csrf()
                    .disable();
    }
    //  AuthenticationManager oauth2授权的时候要用提前加入IOC
    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
```

ServiceOauthConfig

```java
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
```

测试

获取授权码

http://localhost:9002/oauth/authorize?response_type=code&client_id=heima

获取token

![image-20200105234952011](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200105234952011.png)

执行接口

![image-20200105235016737](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20200105235016737.png)