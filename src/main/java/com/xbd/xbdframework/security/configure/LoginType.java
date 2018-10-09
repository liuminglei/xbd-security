package com.xbd.xbdframework.security.configure;

public enum LoginType {

    SESSIONINVALID(1, "会话失效"),

    SESSIONEXPIRED(2, "会话超时"),

    FAILURE(3, "登录失败"),

    USERNAMEORPASSWORDERROR(4, "用户名密码错误"),

    CAPTCHAERROR(5, "登录失败"),

    OTHER(6, "登录异常");

    private int type;

    private String message;

    private LoginType(int type, String message) {
        this.type = type;
        this.message = message;
    }

    public String getMessage(int type) {
        for (LoginType loginType : LoginType.values()) {
            if (loginType.type == type) {
                return loginType.message;
            }
        }

        return null;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
