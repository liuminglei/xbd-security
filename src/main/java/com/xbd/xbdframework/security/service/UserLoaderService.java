package com.xbd.xbdframework.security.service;

import org.springframework.security.core.userdetails.UserDetails;

/**
 * 用户加载服务
 *
 * @author 刘明磊
 * @date 2018/8/29
 */
public interface UserLoaderService {

    UserDetails getUserByUsername(String username);

    UserDetails getUserBySignature(String signature);

}
