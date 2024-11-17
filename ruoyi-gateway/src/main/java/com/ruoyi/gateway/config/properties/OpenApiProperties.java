package com.ruoyi.gateway.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * Created on 2024/11/17 22:55
 *
 * @author 毛智远
 */
@Configuration
@RefreshScope
@ConfigurationProperties(prefix = "security.openapi")
public class OpenApiProperties {
    private List<String> apis = new ArrayList<>();

    public List<String> getApis() {
        return apis;
    }

    public void setApis(List<String> apis) {
        this.apis = apis;
    }
}
