package com.spring.security.dao;

import com.spring.security.domian.SysRole;
import org.apache.ibatis.annotations.Select;
import tk.mybatis.mapper.common.Mapper;

import java.util.List;

public interface RoleMapper extends Mapper<SysRole> {
    @Select("SELECT r.* FROM sys_role r INNER  JOIN  sys_user_role ur ON r.id=ur.roleid where userId = #{userId} ")
    List<SysRole> findByUid(Integer userId);
}
