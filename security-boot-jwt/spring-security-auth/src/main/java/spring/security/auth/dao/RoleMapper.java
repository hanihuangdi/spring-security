package spring.security.auth.dao;

import org.apache.ibatis.annotations.Select;
import spring.security.auth.domian.SysRole;
import tk.mybatis.mapper.common.Mapper;

import java.util.List;

public interface RoleMapper extends Mapper<SysRole> {
    @Select("SELECT r.* FROM sys_role r INNER  JOIN  sys_user_role ur ON r.id=ur.roleid where userId = #{userId} ")
    List<SysRole> findByUid(Integer userId);
}
