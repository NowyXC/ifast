## ifast框架笔记

### 1.拦截防止**xss**注入

配置文件

```java
@Configuration
public class XssConfiguration {

    @Bean
    public FilterRegistrationBean xssFilterRegistrationBean() {
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter(new XssFilter());
        filterRegistrationBean.setOrder(1);
        filterRegistrationBean.setEnabled(true);
        filterRegistrationBean.addUrlPatterns("/*");
        Map<String, String> initParameters = Maps.newHashMap();
        initParameters.put("excludes", "/favicon.ico,/img/*,/js/*,/css/*");
        initParameters.put("isIncludeRichText", "true");
        filterRegistrationBean.setInitParameters(initParameters);
        return filterRegistrationBean;
    }
}
```

主要配置说明：

- **XssFilter过滤器**

  - **excludes**：排除静态资源

  - **isIncludeRichText**:是否过滤富文本

    

**XssFilter过滤器**

```java
/**
 * <pre>
 * 拦截防止xss注入
 * 通过Jsoup过滤请求参数内的特定字符
 * </pre>
 * 
 * <small> 2018年3月23日 | Aron</small>
 */
public class XssFilter implements Filter {
    private static Logger logger = LoggerFactory.getLogger(XssFilter.class);

    /**
     * 是否过滤富文本内容
     */
    private static boolean IS_INCLUDE_RICH_TEXT = false;

    /**
     * 排除的资源列表
     */
    public List<String> excludes = new ArrayList<>();

	//初始化配置
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        if (logger.isDebugEnabled()) {
            logger.debug("xss filter init");
        }
        String isIncludeRichText = filterConfig.getInitParameter("isIncludeRichText");
        if (StringUtils.isNotBlank(isIncludeRichText)) {
            IS_INCLUDE_RICH_TEXT = BooleanUtils.toBoolean(isIncludeRichText);
        }

        String temp = filterConfig.getInitParameter("excludes");
        if (temp != null) {
            String[] url = temp.split(",");
            for (int i = 0; url != null && i < url.length; i++) {
                excludes.add(url[i]);
            }
        }
    }
    
    //过滤操作核心代码
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        if (handleExcludeURL(req, resp)) {
            filterChain.doFilter(request, response);
            return;
        }
		//XssHttpServletRequestWrapper 处理请求
        XssHttpServletRequestWrapper xssRequest = new XssHttpServletRequestWrapper((HttpServletRequest) request,
                IS_INCLUDE_RICH_TEXT);
        filterChain.doFilter(xssRequest, response);
    }
    

    private boolean handleExcludeURL(HttpServletRequest request, HttpServletResponse response) {
        if (excludes == null || excludes.isEmpty()) {
            return false;
        }
        String url = request.getServletPath();
        for (String pattern : excludes) {
            Pattern p = Pattern.compile("^" + pattern);
            Matcher m = p.matcher(url);
            if (m.find()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void destroy() {
    }

}

```

**XssFilter**主要通过doFilter中的**XssHttpServletRequestWrapper**处理请求中的Xss注入。



**XssHttpServletRequestWrapper**

```java
/**
 * <pre>
 * 处理request中的Xss注入,主要处理以下方法
 *    - getParameter(name)
 *    - getParameterValues(name)
 *    - getHeader(name)
 * </pre>
 * <small> 2018年3月23日 | Aron</small>
 */
public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper {  
    HttpServletRequest orgRequest = null;  
    private boolean isIncludeRichText = false;
  
    public XssHttpServletRequestWrapper(HttpServletRequest request, boolean isIncludeRichText) {  
        super(request);  
        orgRequest = request;
        this.isIncludeRichText = isIncludeRichText;
    }  
  
    /** 
    * 覆盖getParameter方法，将参数名和参数值都做xss过滤。<br/> 
    * 如果需要获得原始的值，则通过super.getParameterValues(name)来获取<br/> 
    * getParameterNames,getParameterValues和getParameterMap也可能需要覆盖 
    */  
    @Override  
    public String getParameter(String name) {
        Boolean flag = ("content".equals(name) || name.endsWith("WithHtml"));
        if( flag && !isIncludeRichText){
            return super.getParameter(name);
        }
        name = JsoupUtil.clean(name);
        String value = super.getParameter(name);  
        if (StringUtils.isNotBlank(value)) {
            value = JsoupUtil.clean(value);  
        }
        return value;  
    }  
    
    @Override
    public String[] getParameterValues(String name) {
       String[] arr = super.getParameterValues(name);
       if(arr != null){
          for (int i=0;i<arr.length;i++) {
             arr[i] = JsoupUtil.clean(arr[i]);
          }
       }
       return arr;
    }
    
  
    /** 
    * 覆盖getHeader方法，将参数名和参数值都做xss过滤。<br/> 
    * 如果需要获得原始的值，则通过super.getHeaders(name)来获取<br/> 
    * getHeaderNames 也可能需要覆盖 
    */  
    @Override  
    public String getHeader(String name) {  
        name = JsoupUtil.clean(name);
        String value = super.getHeader(name);  
        if (StringUtils.isNotBlank(value)) {  
            value = JsoupUtil.clean(value); 
        }  
        return value;  
    }  
  
    /** 
    * 获取最原始的request 
    * 
    * @return 
    */  
    public HttpServletRequest getOrgRequest() {  
        return orgRequest;  
    }  
  
    /** 
    * 获取最原始的request的静态方法 
    * 
    * @return 
    */  
    public static HttpServletRequest getOrgRequest(HttpServletRequest req) {  
        if (req instanceof XssHttpServletRequestWrapper) {  
            return ((XssHttpServletRequestWrapper) req).getOrgRequest();  
        }  
  
        return req;  
    }  
  
}  
```

主要是通过重载HttpServletRequestWrapper中的方法：

- getParameter(String name)：name为**content**或者**WithHtml**是，如果不过滤富文本，则不验证
- getParameterValues(String name) 
-  getHeader(String name)

本质上是通过JsoupUtil对Request的[name-value]都进行**非法标签的过滤**



**JsoupUtil**

```java
/**
 * xss非法标签过滤
 * {@link http://www.jianshu.com/p/32abc12a175a?nomobile=yes}
 * @author yangwenkui
 * @version v2.0
 * @time 2017年4月27日 下午5:47:09
 */
public class JsoupUtil {

   /**
    * 使用自带的basicWithImages 白名单
    * 允许的便签有a,b,blockquote,br,cite,code,dd,dl,dt,em,i,li,ol,p,pre,q,small,span,
    * strike,strong,sub,sup,u,ul,img
    * 以及a标签的href,img标签的src,align,alt,height,width,title属性
    */
   private static final Whitelist whitelist = Whitelist.basicWithImages();
   /** 配置过滤化参数,不对代码进行格式化 */
   private static final Document.OutputSettings outputSettings = new Document.OutputSettings().prettyPrint(false);
   static {
      // 富文本编辑时一些样式是使用style来进行实现的
      // 比如红色字体 style="color:red;"
      // 所以需要给所有标签添加style属性
      whitelist.addAttributes(":all", "style");
   }

   public static String clean(String content) {
      return Jsoup.clean(content, "", whitelist, outputSettings);
   }
   
   public static void main(String[] args) throws FileNotFoundException, IOException {
      String text = "<a href=\"http://www.baidu.com/a\" onclick=\"alert(1);\">sss</a><script>alert(0);</script>sss";
      System.out.println(clean(text));
   }

}
```

**jsoup依赖项**

```java
<dependency>
   <groupId>org.jsoup</groupId>
   <artifactId>jsoup</artifactId>
   <version>1.9.2</version>
</dependency>
```





### 2.面向切面的验证器**ValidFormAspect**

以AOP的形式为控制器添加参数校验，暂时只实现了**com.ifast..controller.*.*(..)**下的控制器的处理

**ValidFormAspect**

```java
/**
 * <pre>
 * 全局表单自动验证
 * </pre>
 * <small> 2018年3月22日 | Aron</small>
 */
@Aspect
@Component
public class ValidFormAspect {

    private Logger log = LoggerFactory.getLogger(getClass());

    @Pointcut("execution(* com.ifast..controller.*.*(..))")
    public void validFormAspect() {
    }

    @Around("validFormAspect()")
    public Object around(ProceedingJoinPoint point) throws Throwable {
        // point.getTarget().getClass().getName() 获取调用者
        Object[] args = point.getArgs();//获取传参
        for(Object arg : args){//判断参数对象是否添加了ValidForm注解
            ValidForm validForm = arg.getClass().getAnnotation(ValidForm.class);
            if(validForm != null){//处理对象中的validator,存在异常则抛出
                ValidationResult validationResult = ValidateUtils.validateEntity(arg);
                if(validationResult.isHasErrors()){
                    throw new IllegalArgumentException(validationResult.toString());
                }
            }
        }
        Object result = point.proceed();
        return result;
    }
}
```



**ValidForm**

```java
/**
 * <pre>
 * 自动表单验注解
 * </pre>
 * <small> 2018/9/4 12:00 | Aron</small>
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Inherited
public @interface ValidForm {
}
```

执行流程：

1. 指定包目录下的控制器的调用
2. 进入切面，处理请求参数
3. 请求参数(<u>DTO</u>)带有**ValidForm**注解
4. 进行校验，**ValidateUtils.validateEntity(arg)**

**ValidateUtils**

```java
/**
 * <pre>
 *
 * </pre>
 * <small> 2018/9/4 12:04 | Aron</small>
 */
public class ValidateUtils {

    private static Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    /**
     * 验证对象中的 Validator
     */
    public static <T> ValidationResult validateEntity(T obj) {
        ValidationResult result = new ValidationResult();
        Set<ConstraintViolation<T>> set = validator.validate(obj, Default.class);
        if (ValidateUtils.isNotEmpty(set)) {
            result.setHasErrors(true);
            List<String> errorMsg = new ArrayList<>();
            for (ConstraintViolation<T> cv : set) {
                errorMsg.add(cv.getPropertyPath() + cv.getMessage());
            }
            result.setErrorMsg(errorMsg);
        }
        return result;
    }

    /**
     * 验证对象中指定属性的Validator
     */
    public static <T> ValidationResult validateProperty(T obj, String propertyName) {
        ValidationResult result = new ValidationResult();
        Set<ConstraintViolation<T>> set = validator.validateProperty(obj, propertyName, Default.class);
        if (ValidateUtils.isNotEmpty(set)) {
            result.setHasErrors(true);
            List<String> errorMsg = new ArrayList<>();
            for (ConstraintViolation<T> cv : set) {
                errorMsg.add(cv.getMessageTemplate());
            }
            result.setErrorMsg(errorMsg);
        }
        return result;
    }

    private static boolean isNotEmpty(Collection<?> c) {
        return (c != null) && (!c.isEmpty());
    }
}
```



**ValidationResult**

```java
/**
 * 
 * @author Aron
 * @date 2017年8月4日
 */
public class ValidationResult {
   
   //校验结果是否有错
   private boolean hasErrors;
   
   //校验错误信息
// private Map<String,String> errorMsg;
   private List<String> errorMsg;
   

   public boolean isHasErrors() {
      return hasErrors;
   }

   public void setHasErrors(boolean hasErrors) {
      this.hasErrors = hasErrors;
   }
   

   public List<String> getErrorMsg() {
      return errorMsg;
   }

   public void setErrorMsg(List<String> errorMsg) {
      this.errorMsg = errorMsg;
   }

   @Override
   public String toString() {
      String content = "" ;
      if(errorMsg.size()>0){
         content=errorMsg.get(0);
      }
//    for(int i = 0; i < errorMsg.size(); i++) {
//       if (i != errorMsg.size() - 1) {
//          content = content + errorMsg.get(i) + ",";
//       }
//       if (i == errorMsg.size() - 1) {
//          content = content + errorMsg.get(i);
//       }
//    }
      return content;
   }

}
```



**测试示例：**

```java
@RestController
@RequestMapping("/test")
public class TestController {
    @PostMapping("/valid")
    public void valid(@RequestBody TestValidDTO dto) {
        System.out.println(dto);
    }
}

@ValidForm
@Data
public class TestValidDTO {

    @NotNull
    @Length(max = 20, min = 6)
    private String name;

    @NotNull
    @Range(min = 1, max = 120)
    private Integer age;

    @NotNull
    @Range(min = 1, max = 3)
    private Integer sex;
}
```





### 3.切面日志**LogAspect**

通过注解+切面的形式，为Controller配置日志输出，主要配置包含：

- 匹配带有@Log的方法
- 匹配符合规则的Controller、Service、BaseMapper

**LogAspect**

```java
/**
 * <pre>
 * 日志切面
 * </pre>
 * <small> 2018年3月22日 | Aron</small>
 */
@Aspect
@Component
@Slf4j
@Data
@AllArgsConstructor
public class LogAspect {

    private LogDao logMapper;

    /** 匹配持有Log注解的方法 */
    @Pointcut("@annotation(com.ifast.common.annotation.Log)")
    public void logPointCut() {
    }

    @Around("logPointCut()")
    public Object around(ProceedingJoinPoint point) throws Throwable {
        long beginTime = System.currentTimeMillis();
        // 执行方法
        Object result = point.proceed();
        // 执行时长(毫秒)
        long time = System.currentTimeMillis() - beginTime;
        // 保存日志
        saveLog(point, time);
        return result;
    }
    
    @Pointcut("execution(public * com.ifast.*.controller.*.*(..))")
    public void logController(){}
    
    /** 记录controller日志，包括请求、ip、参数、响应结果 */
    @Around("logController()")
    public Object controller(ProceedingJoinPoint point) throws Throwable {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        log.info("{} {} {} {}.{}{}", request.getMethod(), request.getRequestURI(), IPUtils.getIpAddr(request), point.getTarget().getClass().getSimpleName(), point.getSignature().getName(), Arrays.toString(point.getArgs()));
        
        long beginTime = System.currentTimeMillis();
        Object result = point.proceed();
        long time = System.currentTimeMillis() - beginTime;
        
        log.info("result({}) {}", time, JSONUtils.beanToJson(result));
        return result;
    }
    
    @Pointcut("execution(public * com.ifast.*.service.*.*(..))")
    public void logService(){}
    
    /** 记录自定义service接口日志，如果要记录CoreService所有接口日志请仿照logMapper切面 */
    @Around("logService()")
    public Object service(ProceedingJoinPoint point) throws Throwable {
       log.info("call {}.{}{}", point.getTarget().getClass().getSimpleName(), point.getSignature().getName(), Arrays.toString(point.getArgs()));
       
       long beginTime = System.currentTimeMillis();
       Object result = point.proceed();
       long time = System.currentTimeMillis() - beginTime;
       
       log.info("result({}) {}", time, result instanceof Serializable ? JSONUtils.beanToJson(result) : result);
       return result;
    }

    /** BaseMapper类型或者其子类 */
    @Pointcut("within(com.baomidou.mybatisplus.mapper.BaseMapper+)")
    public void logMapper(){}
    
    /** 记录mapper所有接口日志，设置createBy和updateBy基础字段，logback会记录sql，这里记录查库返回对象 */
    @Around("logMapper()")
    public Object mapper(ProceedingJoinPoint point) throws Throwable {
       String methodName = point.getSignature().getName();
       boolean insertBy = isInsert(methodName);
        boolean updateBy = isUpdate(methodName);

       if(insertBy || updateBy) {
          Object arg0 = point.getArgs()[0];
          if(arg0 instanceof BaseDO) {
             Long userId = ShiroUtils.getUserId();
             if(userId != null) {
                BaseDO baseDO = (BaseDO)arg0;
                if(insertBy) {
                   baseDO.setCreateBy(userId);
                }else {
                   baseDO.setUpdateBy(userId);
                }
             }
          }
       }
       
       log.info("call {}.{}{}", point.getTarget().getClass().getSimpleName(), methodName, Arrays.toString(point.getArgs()));
       long beginTime = System.currentTimeMillis();
       Object result = point.proceed();
       long time = System.currentTimeMillis() - beginTime;
       
       log.info("result({}) {}", time, JSONUtils.beanToJson(result));
       return result;
    }

    private boolean isUpdate(String methodName) {
        return "update".equals(methodName) || "updateById".equals(methodName) || "updateAllColumn".equals(methodName);
    }

    private boolean isInsert(String methodName) {
        return "insert".equals(methodName) || "insertAllColumn".equals(methodName);
    }

    /**
     * <pre>
     * 保存日志
     * </pre>
     * <small> 2018年3月22日 | Aron</small>
     * @param joinPoint
     * @param time
     */
    private void saveLog(ProceedingJoinPoint joinPoint, long time) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        LogDO sysLog = new LogDO();
        Log syslog = method.getAnnotation(Log.class);
        if (syslog != null) {
            // 注解上的描述
            sysLog.setOperation(syslog.value());
        }
        // 请求的方法名
        String className = joinPoint.getTarget().getClass().getName();
        String methodName = signature.getName();
        String params = null;
        HttpServletRequest request = HttpContextUtils.getHttpServletRequest();
        if(request != null) {
           sysLog.setMethod(request.getMethod()+" "+request.getRequestURI());
           Map<String, String[]> parameterMap = request.getParameterMap();
           params = JSONUtils.beanToJson(parameterMap);
           // 设置IP地址
           sysLog.setIp(IPUtils.getIpAddr(request));
        }else {
           sysLog.setMethod(className + "." + methodName + "()");
           Object[] args = joinPoint.getArgs();
           params = JSONUtils.beanToJson(args);
        }
        int maxLength = 4999;
        if(params.length() > maxLength){
           params = params.substring(0, maxLength);
        }
        sysLog.setParams(params);
        // 用户名
       UserDO currUser = ShiroUtils.getSysUser();
       if (null == currUser) {
          sysLog.setUserId(-1L);
          sysLog.setUsername("");
       } else {
          sysLog.setUserId(currUser.getId());
          sysLog.setUsername(currUser.getUsername());
       }
        sysLog.setTime((int) time);
        // 系统当前时间
        Date date = new Date();
        sysLog.setGmtCreate(date);
        // 保存系统日志
        logMapper.insert(sysLog);
    }
}
```



**logback-spring.xml**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!-- 日志级别从低到高分为TRACE < DEBUG < INFO < WARN < ERROR < FATAL，如果设置为WARN，则低于WARN的信息都不会输出 -->
<!-- scan:当此属性设置为true时，配置文档如果发生改变，将会被重新加载，默认值为true -->
<!-- scanPeriod:设置监测配置文档是否有修改的时间间隔，如果没有给出时间单位，默认单位是毫秒。 当scan为true时，此属性生效。默认的时间间隔为1分钟。 -->
<!-- debug:当此属性设置为true时，将打印出logback内部日志信息，实时查看logback运行状态。默认值为false。 -->
<configuration scanPeriod="10 seconds" scan="true" >
    <contextName>logback</contextName>
    <!--日志路径-->
    <springProfile name="dev">
        <property name="log.path" value="logs" />
    </springProfile>

    <springProfile name="test,prod">
        <property name="log.path" value="/home/server/logs" />
    </springProfile>

    <!--0. 日志格式和颜色渲染 -->
    <!-- 彩色日志依赖的渲染类 -->
    <conversionRule converterClass="org.springframework.boot.logging.logback.ColorConverter" conversionWord="clr"/>
    <conversionRule converterClass="org.springframework.boot.logging.logback.WhitespaceThrowableProxyConverter" conversionWord="wex"/>
    <conversionRule converterClass="org.springframework.boot.logging.logback.ExtendedWhitespaceThrowableProxyConverter" conversionWord="wEx"/>
    <!-- 彩色日志格式 -->
    <property value="${CONSOLE_LOG_PATTERN:-%clr(%d{yyyy-MM-dd HH:mm:ss.SSS}){faint} %clr(${LOG_LEVEL_PATTERN:-%5p}) %clr(${PID:- }){magenta} %clr(---){faint} %clr([%15.15t]){faint} %clr(%-40.40logger{39}){cyan} %clr(:){faint} %m%n${LOG_EXCEPTION_CONVERSION_WORD:-%wEx}}" name="CONSOLE_LOG_PATTERN"/>

    <!--1. 输出到控制台-->
    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <!--此日志appender是为开发使用，只配置最底级别，控制台输出的日志级别是大于或等于此级别的日志信息-->
        <filter class="ch.qos.logback.classic.filter.ThresholdFilter">
            <level>debug</level>
        </filter>
        <encoder>
            <Pattern>${CONSOLE_LOG_PATTERN}</Pattern>
            <!-- 设置字符集 -->
            <charset>UTF-8</charset>
        </encoder>
    </appender>

    <!--2. 输出到文档-->
    <!-- 2.1 level为 DEBUG 日志，时间滚动输出 -->
    <appender name="DEBUG_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <!-- 正在记录的日志文档的路径及文档名 -->
        <file>${log.path}/debug.log</file>
        <!--日志文档输出格式-->
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
            <charset>UTF-8</charset>
            <!-- 设置字符集 -->
        </encoder>
        <!-- 日志记录器的滚动策略，按日期，按大小记录 -->
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <!-- 日志归档 -->
            <fileNamePattern>${log.path}/debug-%d{yyyy-MM-dd}.%i.log</fileNamePattern>
            <timeBasedFileNamingAndTriggeringPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedFNATP">
                <maxFileSize>100MB</maxFileSize>
            </timeBasedFileNamingAndTriggeringPolicy>
            <!--日志文档保留天数-->
            <maxHistory>10</maxHistory>
        </rollingPolicy>
        <!-- 此日志文档只记录debug级别的 -->
        <filter class="ch.qos.logback.classic.filter.LevelFilter">
            <level>debug</level>
            <onMatch>ACCEPT</onMatch>
            <onMismatch>DENY</onMismatch>
        </filter>
    </appender>

    <!-- 2.2 level为 INFO 日志，时间滚动输出 -->
    <appender name="INFO_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <!-- 正在记录的日志文档的路径及文档名 -->
        <file>${log.path}/info.log</file>
        <!--日志文档输出格式-->
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
            <charset>UTF-8</charset>
        </encoder>
        <!-- 日志记录器的滚动策略，按日期，按大小记录 -->
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <!-- 每天日志归档路径以及格式 -->
            <fileNamePattern>${log.path}/info-%d{yyyy-MM-dd}.%i.log</fileNamePattern>
            <timeBasedFileNamingAndTriggeringPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedFNATP">
                <maxFileSize>50MB</maxFileSize>
            </timeBasedFileNamingAndTriggeringPolicy>
            <!--日志文档保留天数-->
            <maxHistory>10</maxHistory>
        </rollingPolicy>
        <!-- 此日志文档只记录info级别的 -->
        <filter class="ch.qos.logback.classic.filter.LevelFilter">
            <level>info</level>
            <onMatch>ACCEPT</onMatch>
            <onMismatch>DENY</onMismatch>
        </filter>
    </appender>

    <!-- 2.3 level为 WARN 日志，时间滚动输出 -->
    <appender name="WARN_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <!-- 正在记录的日志文档的路径及文档名 -->
        <file>${log.path}/warn.log</file>
        <!--日志文档输出格式-->
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
            <charset>UTF-8</charset>
            <!-- 此处设置字符集 -->
        </encoder>
        <!-- 日志记录器的滚动策略，按日期，按大小记录 -->
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>${log.path}/warn-%d{yyyy-MM-dd}.%i.log</fileNamePattern>
            <timeBasedFileNamingAndTriggeringPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedFNATP">
                <maxFileSize>50MB</maxFileSize>
            </timeBasedFileNamingAndTriggeringPolicy>
            <!--日志文档保留天数-->
            <maxHistory>10</maxHistory>
        </rollingPolicy>
        <!-- 此日志文档只记录warn级别的 -->
        <filter class="ch.qos.logback.classic.filter.LevelFilter">
            <level>warn</level>
            <onMatch>ACCEPT</onMatch>
            <onMismatch>DENY</onMismatch>
        </filter>
    </appender>

    <!-- 2.4 level为 ERROR 日志，时间滚动输出 -->
    <appender name="ERROR_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <!-- 正在记录的日志文档的路径及文档名 -->
        <file>${log.path}/error.log</file>
        <!--日志文档输出格式-->
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n</pattern>
            <charset>UTF-8</charset>
            <!-- 此处设置字符集 -->
        </encoder>
        <!-- 日志记录器的滚动策略，按日期，按大小记录 -->
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>${log.path}/error-%d{yyyy-MM-dd}.%i.log</fileNamePattern>
            <timeBasedFileNamingAndTriggeringPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedFNATP">
                <maxFileSize>50MB</maxFileSize>
            </timeBasedFileNamingAndTriggeringPolicy>
            <!--日志文档保留天数-->
            <maxHistory>10</maxHistory>
        </rollingPolicy>
        <!-- 此日志文档只记录ERROR级别的 -->
        <filter class="ch.qos.logback.classic.filter.LevelFilter">
            <level>ERROR</level>
            <onMatch>ACCEPT</onMatch>
            <onMismatch>DENY</onMismatch>
        </filter>
    </appender>
    <!-- <logger>用来设置某一个包或者具体的某一个类的日志打印级别、 以及指定<appender>。
    <logger>仅有一个name属性， 一个可选的level和一个可选的addtivity属性。
    name:用来指定受此logger约束的某一个包或者具体的某一个类。
    level:用来设置打印级别，大小写无关：TRACE, DEBUG, INFO, WARN, ERROR, ALL 和 OFF，
    还有一个特俗值INHERITED或者同义词NULL，代表强制执行上级的级别。
    如果未设置此属性，那么当前logger将会继承上级的级别。
    addtivity:是否向上级logger传递打印信息。默认是true。
    <logger name="org.springframework.web" level="info"/>
    <logger name="org.springframework.scheduling.annotation.ScheduledAnnotationBeanPostProcessor" level="INFO"/>
    -->
    <!-- 使用mybatis的时候，sql语句是debug下才会打印，
    而这里我们只配置了info，
    所以想要查看sql语句的话，有以下两种操作：
    第一种把<root level="info">改成<root level="DEBUG">这样就会打印sql，
    不过这样日志那边会出现很多其他消息

    第二种就是单独给dao下目录配置debug模式，
    代码如下，这样配置sql语句会打印，其他还是正常info级别：
    【logging.level.org.mybatis=debug logging.level.dao=debug】
    -->
    <!-- root节点是必选节点，用来指定最基础的日志输出级别，
    只有一个level属性 level:用来设置打印级别，
    大小写无关：TRACE, DEBUG, INFO, WARN, ERROR, ALL 和 OFF，
    不能设置为INHERITED或者同义词NULL。
    默认是DEBUG 可以包含零个或多个元素，标识这个appender将会添加到这个logger。 -->

    <!-- 4. 最终的策略 -->
    <!-- 4.1 开发环境:打印控制台-->
    <springProfile name="dev">
        <logger name="com.ifast" level="debug"/>
        <logger name="springfox.documentation" level="error"/>
        <logger name="org.springframework.web.servlet.mvc.method.annotation" level="error"/>
        <logger name="org.springframework.context.support" level="error"/>
        <root level="info">
            <appender-ref ref="CONSOLE" />
        </root>
    </springProfile>

    <!-- 4.2 生产环境:输出到文档 -->
    <springProfile name="prod,test">
        <logger name="springfox.documentation" level="error"/>
        <root level="info">
            <appender-ref ref="CONSOLE" />
            <appender-ref ref="DEBUG_FILE" />
            <appender-ref ref="INFO_FILE" />
            <appender-ref ref="ERROR_FILE" />
            <appender-ref ref="WARN_FILE" />
        </root>
    </springProfile>
</configuration>
```



**使用示例：**

```java
/**
 * 保存
 */
@Log("添加数据字典")
@ResponseBody
@PostMapping("/save")
@RequiresPermissions("common:sysDict:add")
public Result<String> save(DictDO sysDict) {
    sysDictService.insert(sysDict);
    return Result.ok();
}
```





### 4.缓存配置CacheConfiguration

缓存配置（`org.springframework.cache.Cache`和`org.springframework.cache.CacheManager`）

[SpringBoot Cache 详解]: https://blog.csdn.net/elong490/article/details/96864095	"史上最全的Spring Boot Cache使用与整合"

策略:

1. 默认ehcache
2. 如果配置spring.redis.host 则使用redis（application.yml中）



**依赖项：**

```xml
<!-- ehchache -->
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-cache</artifactId>
</dependency>
<dependency>
   <groupId>net.sf.ehcache</groupId>
   <artifactId>ehcache</artifactId>
</dependency>

<!-- data-redis S -->
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
<!-- data-redis E -->

<!-- shiro ehcache -->
<dependency>
	<groupId>org.apache.shiro</groupId>
	<artifactId>shiro-ehcache</artifactId>
	<version>1.3.2</version>
</dependency>
```



**CacheConfiguration(缓存配置类)**

```java
/**
 * 缓存配置
 * 策略:
 * 1. 默认ehcache
 * 2. 如果配置spring.redis.host 则使用redis
 */
@Configuration
@EnableCaching
public class CacheConfiguration {

   private static Logger log = LoggerFactory.getLogger(CacheConfiguration.class);

   /** 配置spring.redis.host时使用RedisCacheManager，否则使用EhCacheCacheManager */
   @Bean
    @ConditionalOnProperty(prefix="spring.redis", name="host", havingValue="false", matchIfMissing=true)
   public EhCacheManagerFactoryBean ehCacheManagerFactoryBean() {
      EhCacheManagerFactoryBean cacheManagerFactoryBean = new EhCacheManagerFactoryBean();
      cacheManagerFactoryBean.setConfigLocation(new ClassPathResource("config/ehcache.xml"));
      cacheManagerFactoryBean.setShared(true);
      return cacheManagerFactoryBean;
   }

   /** 不存在则自动创建name的缓存 */
    @Bean
    @ConditionalOnBean(EhCacheManagerFactoryBean.class)
    public EhCacheCacheManager ehCacheCacheManager(EhCacheManagerFactoryBean ehCacheManagerFactoryBean) {
        return new EhCacheCacheManager(ehCacheManagerFactoryBean.getObject()) {
         @Override
         protected Cache getMissingCache(String name) {
            Cache cache = super.getMissingCache(name);
            if (cache == null) {
               //使用default配置克隆缓存
               getCacheManager().addCacheIfAbsent(name);
               cache = super.getCache(name);
            }
            return cache;
         }
        };
    }

    /**
     *  动态配置缓存，
     *  示例：<code>Cache fiveMinutes = CacheConfiguration.dynaConfigCache("5min", 300);</code>
     */
    @SuppressWarnings("unchecked")
    public static Cache dynaConfigCache(String name, long timeToLiveSeconds) {
       CacheManager cacheManager = SpringContextHolder.getBean(CacheManager.class);
       if(cacheManager instanceof RedisCacheManager) {
          if(log.isDebugEnabled()){
            log.debug("使用RedisCacheManager");
         }
         Field expiresField = ReflectionUtils.findField(RedisCacheManager.class, "expires");
         ReflectionUtils.makeAccessible(expiresField);
         Map<String, Long> expires = (Map<String, Long>)ReflectionUtils.getField(expiresField, cacheManager);
         if(expires == null) {
            ReflectionUtils.setField(expiresField, cacheManager, expires = new HashMap<>());
         }
         expires.put(name, timeToLiveSeconds);
      }else if(cacheManager instanceof EhCacheCacheManager) {
         if(log.isDebugEnabled()){
            log.debug("使用EhCacheCacheManager");
         }
         net.sf.ehcache.Cache ehCacheCache = (net.sf.ehcache.Cache)cacheManager.getCache(name).getNativeCache();
          net.sf.ehcache.config.CacheConfiguration cacheConfiguration = ehCacheCache.getCacheConfiguration();
          cacheConfiguration.timeToLiveSeconds(timeToLiveSeconds);
       }
       return cacheManager.getCache(name);
    }
}
```

缓存策略：

检测application.yml中是否配置了redis（spring.redis.host），如果存在则使用redis,不存在则使用ehcache

动态调用示例代码：

```java
Cache fiveMinutes = CacheConfiguration.dynaConfigCache("5min", 300);
```

```java
/** 静态内部类延时加载 */
public static class Holder {
   public static final JWTConfigProperties jwtConfig = SpringContextHolder.getBean(JWTConfigProperties.class);
   public static final Cache logoutTokens = CacheConfiguration.dynaConfigCache(jwtConfig.getExpireTokenKeyPrefix(), jwtConfig
               .getRefreshTokenExpire());
}
```



**ehcache.xml**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ehcache xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:noNamespaceSchemaLocation="http://ehcache.org/ehcache.xsd"
   updateCheck="false">
   
    <!--
        磁盘存储:将缓存中暂时不使用的对象,转移到硬盘,类似于Windows系统的虚拟内存
        path:指定在硬盘上存储对象的路径
        path可以配置的目录有：
            user.home（用户的家目录）
            user.dir（用户当前的工作目录）
            java.io.tmpdir（默认的临时目录）
            ehcache.disk.store.dir（ehcache的配置目录）
            绝对路径（如：d:\\ehcache）
        查看路径方法：String tmpDir = System.getProperty("java.io.tmpdir");
     -->
   <diskStore path="java.io.tmpdir/Tmp_EhCache" />
   
   <defaultCache eternal="false" maxElementsInMemory="1000"
      overflowToDisk="false" 
      diskPersistent="false" 
      timeToIdleSeconds="0"
      timeToLiveSeconds="600" 
      memoryStoreEvictionPolicy="LRU" 
   />
   
    <!-- 代码中使用：@CacheConfig(cacheNames = {“role”}) 或者 @Cacheable(value=”role”)-->
   <cache name="role" 
      eternal="false" 
      maxElementsInMemory="10000"
      overflowToDisk="false" 
      diskPersistent="false" 
      timeToIdleSeconds="0"
      timeToLiveSeconds="0" 
      memoryStoreEvictionPolicy="LFU" 
    />
</ehcache>
```



在Shiro中可以配置自定义的CacheManager，详情请查看[Shiro使用](#6.Shiro使用)





### 5.Swagger2

### 6.Shiro使用

### 7.Quartz使用

### 8.velocity代码模板

MyBatis-Plus默认是使用velocity作为自动生成代码的模板引擎。

velocity模板引擎的文件一般存放在`resources/templates`目录下，格式：`*.vm`

### 9.thymeleaf使用

### 10.Mybatis-Plus使用