package security.oauth.source.dao;

import org.apache.ibatis.annotations.Select;
import security.oauth.source.domain.SysRole;

import java.util.List;

public interface RoleMapper {
    @Select("SELECT r.* FROM sys_role r INNER  JOIN  sys_user_role ur ON r.id=ur.roleid where userId = #{userId} ")
    List<SysRole> findByUid(Integer userId);
}
