package com.ifast.common.validation;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

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
