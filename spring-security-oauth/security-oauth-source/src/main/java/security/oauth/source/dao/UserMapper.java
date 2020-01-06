package security.oauth.source.dao;

import org.apache.ibatis.annotations.Many;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;
import security.oauth.source.domain.SysUser;

import java.util.List;

public interface UserMapper{

    @Select("select * from sys_user where username = #{username}")
    @Results({
            @Result(id=true,column = "id",property = "id"),
            @Result(column = "username",property = "username"),
            @Result(column = "password",property = "password"),
            @Result(column = "status",property = "status"),
            @Result(column = "id",property = "roles",javaType = List.class,many=@Many(select = "security.oauth.source.dao.RoleMapper.findByUid")),

    })
    SysUser findByName(String username);
}
