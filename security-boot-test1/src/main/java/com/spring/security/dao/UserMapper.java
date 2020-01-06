package com.spring.security.dao;

import com.spring.security.domian.SysUser;
import org.apache.ibatis.annotations.Many;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;
import tk.mybatis.mapper.common.Mapper;

import java.util.List;

public interface UserMapper  extends Mapper<SysUser> {

    @Select("select * from sys_user where username = #{username}")
    @Results({
            @Result(id=true,column = "id",property = "id"),
            @Result(column = "id",property = "roles",javaType = List.class,many=@Many(select = "com.spring.security.dao.RoleMapper.findByUid")),

    })
    SysUser findByName(String username);
}
