package com.spring.security.advice;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

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
