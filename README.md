# xbd-security

#### 项目介绍
基于Spring Security的二次封装安全框架，配置简单易懂，使用方便，已集成90%的内容，只需实现少量内容即可使用Spring Security安全框架

#### 软件架构
    1. Spring Security 5.0.8.RELEASE
    
    2. spring framework 5.0.8.RELEASE
    
    3. slf4j 1.7.25

#### 起步
下载源码，打包引入
#### 配置
```java
package com.xbd.xbdframework.security.test.config;

import com.xbd.xbdframework.security.configure.AbstractWebSecurityConfigurer;
import com.xbd.xbdframework.security.configure.WebSecurityProperties;
import com.xbd.xbdframework.security.service.ResourcesLoaderService;
import com.xbd.xbdframework.security.service.UserLoaderService;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SpringSecurityConfig extends AbstractWebSecurityConfigurer {

    @Bean
    @ConfigurationProperties(prefix = "xbd.security")
    @Override
    public WebSecurityProperties webSecurityProperties() {
        return super.webSecurityProperties();
    }

    @Override
    protected UserLoaderService userLoaderService() {
        return new UserLoaderServiceImpl();
    }

    @Override
    public ResourcesLoaderService resourcesLoaderService() {
        return new ResourcesLoaderServiceImpl();
    }
}
```
#### 配置项说明
##### LoginProperties
<table>
    <tr>
        <td>配置项</td>
        <td>说明</td>
        <td>默认值</td>
    </tr>
    <tr>
        <td>loginProcessingUrl</td>
        <td>spring security默认拦截路径</td>
        <td>无，spring security默认为/login</td>
    </tr>
    <tr>
        <td>loginPage</td>
        <td>登录页</td>
        <td>/login，spring security默认为/login</td>
    </tr>
    <tr>
        <td>defaultSuccessUrl</td>
        <td>登录成功页</td>
        <td>无</td>
    </tr>
    <tr>
        <td>defaultFailureUrl</td>
        <td>默认登录失败页</td>
        <td>loginPage?type=LoginType.FAILURE</td>
    </tr>
    <tr>
        <td>captchaErrorUrl</td>
        <td>验证码错误页</td>
        <td>loginPage?type=LoginType.CAPTCHAERROR</td>
    </tr>
    <tr>
        <td>otherExceptionUrl</td>
        <td>其它异常页</td>
        <td>loginPage?type=LoginType.OTHEREXCEPTION</td>
    </tr>
    <tr>
        <td>defaultSsoLoginUrl</td>
        <td>默认单点登录页</td>
        <td>/sso/login</td>
    </tr>
</table>

##### AntMatchersProperties
<table>
    <tr>
        <td>配置项</td>
        <td>说明</td>
        <td>默认值</td>
    </tr>
    <tr>
        <td>unAuthenticateUrls</td>
        <td>不授权即可访问的路径</td>
        <td>无</td>
    </tr>
    <tr>
        <td>webIgnoreUrls</td>
        <td>spring security忽略资源路径</td>
        <td>"/config/**", "/css/**", "/fonts/**", "/img/**", "/js/**"</td>
    </tr>
</table>

##### SessionManagementProperties
<table>
    <tr>
        <td>配置项</td>
        <td>说明</td>
        <td>默认值</td>
    </tr>
    <tr>
        <td>sessionInvalidUrl</td>
        <td>无效session跳转页</td>
        <td>loginPage?type=LoginType.SESSIONINVALID</td>
    </tr>
    <tr>
        <td>sessionExpiredUrl</td>
        <td>session失效跳转页</td>
        <td>loginPage?type=LoginType.SESSIONEXPIRED</td>
    </tr>
    <tr>
        <td>maximumSessions</td>
        <td>session最大值</td>
        <td>1</td>
    </tr>
    <tr>
        <td>maxSessionsPreventsLogin</td>
        <td>session达到最大值之后是否阻值后续登录</td>
        <td>true</td>
    </tr>
</table>

##### RememberMeProperties
后续扩展
##### LogoutProperties
<table>
    <tr>
        <td>配置项</td>
        <td>说明</td>
        <td>默认值</td>
    </tr>
    <tr>
        <td>logoutUrl</td>
        <td>退出登录页</td>
        <td>无，spring security默认为/logout</td>
    </tr>
    <tr>
        <td>logoutSuccessUrl</td>
        <td>退出登录成功页</td>
        <td>无，spring security默认为/login?logout</td>
    </tr>
    <tr>
        <td>invalidateHttpSession</td>
        <td>是否将session置为无效</td>
        <td>true</td>
    </tr>
    <tr>
        <td>clearAuthentication</td>
        <td>是否清除授权信息</td>
        <td>true</td>
    </tr>
</table>

#### 开发

##### UserLoaderService
```java
package com.xbd.xbdframework.security.test.service;

import com.xbd.xbdframework.security.service.UserLoaderService;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

public class UserLoaderServiceImpl implements UserLoaderService {

    @Override
    public UserDetails getUserByUsername(String s) {
        return new User("账号", "密码", AuthorityUtils.createAuthorityList(new String[] {}));
    }

    @Override
    public UserDetails getUserBySignature(String s) {
        return new User("账号", "密码", AuthorityUtils.createAuthorityList(new String[] {}));
    }
}
```
##### ResourcesLoaderService
```java
package com.xbd.xbdframework.security.test.service;

import com.xbd.xbdframework.security.service.ResourcesLoaderService;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class ResourcesLoaderServiceImpl implements ResourcesLoaderService {
    @Override
    public Map<String, Collection<String>> loadResources() {
        return new HashMap<>();
    }
}
```

##### SpringSecurityConfig
```java
package com.xbd.xbdframework.security.test.config;

import com.xbd.xbdframework.security.configure.AbstractWebSecurityConfigurer;
import com.xbd.xbdframework.security.configure.WebSecurityProperties;
import com.xbd.xbdframework.security.service.ResourcesLoaderService;
import com.xbd.xbdframework.security.service.UserLoaderService;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SpringSecurityConfig extends AbstractWebSecurityConfigurer {

    @Bean
    @ConfigurationProperties(prefix = "xbd.security")
    @Override
    public WebSecurityProperties webSecurityProperties() {
        return super.webSecurityProperties();
    }

    @Override
    protected UserLoaderService userLoaderService() {
        return new UserLoaderServiceImpl();
    }

    @Override
    public ResourcesLoaderService resourcesLoaderService() {
        return new ResourcesLoaderServiceImpl();
    }
}
```

#### 注意事项
    1. 密码加密方式默认为BCryptPasswordEncoder，如有需要，可覆盖
    2. invalidateHttpSession属性为true时，/login?logout默认302到session失效页，为false时，可停留在/login?logout页
