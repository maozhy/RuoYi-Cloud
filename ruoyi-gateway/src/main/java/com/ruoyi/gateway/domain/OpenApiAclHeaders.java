package com.ruoyi.gateway.domain;

/**
 * Created on 2024/11/17 22:54
 *
 * @author 毛智远
 */
public class OpenApiAclHeaders {
    private String contentmd5;
    private String requestdate;
    private String accesskey;
    private String hmac;

    public String getContentmd5() {
        return contentmd5;
    }

    public void setContentmd5(String contentmd5) {
        this.contentmd5 = contentmd5;
    }

    public String getRequestdate() {
        return requestdate;
    }

    public void setRequestdate(String requestdate) {
        this.requestdate = requestdate;
    }

    public String getAccesskey() {
        return accesskey;
    }

    public void setAccesskey(String accesskey) {
        this.accesskey = accesskey;
    }

    public String getHmac() {
        return hmac;
    }

    public void setHmac(String hmac) {
        this.hmac = hmac;
    }
}
