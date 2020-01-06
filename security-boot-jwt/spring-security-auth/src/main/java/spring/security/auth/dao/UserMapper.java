package spring.security.auth.dao;

import org.apache.ibatis.annotations.Many;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;
import spring.security.auth.domian.SysUser;
import tk.mybatis.mapper.common.Mapper;

import java.util.List;

public interface UserMapper  extends Mapper<SysUser> {

    @Select("select * from sys_user where username = #{username}")
    @Results({
            @Result(id=true,column = "id",property = "id"),
            @Result(column = "username",property = "username"),
            @Result(column = "password",property = "password"),
            @Result(column = "status",property = "status"),
            @Result(column = "id",property = "roles",javaType = List.class,many=@Many(select = "spring.security.auth.dao.RoleMapper.findByUid")),

    })
    SysUser findByName(String username);
}
