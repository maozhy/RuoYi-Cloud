package com.ruoyi.gateway.filter;

import com.alibaba.fastjson2.JSONObject;
import com.ruoyi.common.core.constant.CacheConstants;
import com.ruoyi.common.core.constant.HttpStatus;
import com.ruoyi.common.core.constant.SecurityConstants;
import com.ruoyi.common.core.constant.TokenConstants;
import com.ruoyi.common.core.exception.ServiceException;
import com.ruoyi.common.core.utils.JwtUtils;
import com.ruoyi.common.core.utils.ServletUtils;
import com.ruoyi.common.core.utils.StringUtils;
import com.ruoyi.common.redis.service.RedisService;
import com.ruoyi.gateway.config.properties.IgnoreWhiteProperties;
import com.ruoyi.gateway.config.properties.OpenApiProperties;
import com.ruoyi.gateway.domain.OpenApiAclHeaders;
import io.jsonwebtoken.Claims;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.codec.HttpMessageReader;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.server.HandlerStrategies;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.TreeMap;

/**
 * 网关鉴权
 *
 * @author ruoyi
 */
@Component
public class AuthFilter implements GlobalFilter, Ordered
{
    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    // 排除过滤的 uri 地址，nacos自行添加
    @Autowired
    private IgnoreWhiteProperties ignoreWhite;

    @Autowired
    private RedisService redisService;

    @Autowired
    private OpenApiProperties openApi;


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain)
    {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpRequest.Builder mutate = request.mutate();

        String url = request.getURI().getPath();
        // 跳过不需要验证的路径
        if (StringUtils.matches(url, ignoreWhite.getWhites()))
        {
            return chain.filter(exchange);
        }
        if (StringUtils.matches(url, openApi.getApis())) {
            return openApiAcl(exchange, chain);
        }
        String token = getToken(request);
        if (StringUtils.isEmpty(token))
        {
            return unauthorizedResponse(exchange, "令牌不能为空");
        }
        Claims claims = JwtUtils.parseToken(token);
        if (claims == null)
        {
            return unauthorizedResponse(exchange, "令牌已过期或验证不正确！");
        }
        String userkey = JwtUtils.getUserKey(claims);
        boolean islogin = redisService.hasKey(getTokenKey(userkey));
        if (!islogin)
        {
            return unauthorizedResponse(exchange, "登录状态已过期");
        }
        String userid = JwtUtils.getUserId(claims);
        String username = JwtUtils.getUserName(claims);
        if (StringUtils.isEmpty(userid) || StringUtils.isEmpty(username))
        {
            return unauthorizedResponse(exchange, "令牌验证失败");
        }

        // 设置用户信息到请求
        addHeader(mutate, SecurityConstants.USER_KEY, userkey);
        addHeader(mutate, SecurityConstants.DETAILS_USER_ID, userid);
        addHeader(mutate, SecurityConstants.DETAILS_USERNAME, username);
        // 内部请求来源参数清除
        removeHeader(mutate, SecurityConstants.FROM_SOURCE);
        return chain.filter(exchange.mutate().request(mutate.build()).build());
    }

    private void addHeader(ServerHttpRequest.Builder mutate, String name, Object value)
    {
        if (value == null)
        {
            return;
        }
        String valueStr = value.toString();
        String valueEncode = ServletUtils.urlEncode(valueStr);
        mutate.header(name, valueEncode);
    }

    private void removeHeader(ServerHttpRequest.Builder mutate, String name)
    {
        mutate.headers(httpHeaders -> httpHeaders.remove(name)).build();
    }

    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange, String msg)
    {
        log.error("[鉴权异常处理]请求路径:{},错误信息:{}", exchange.getRequest().getPath(), msg);
        return ServletUtils.webFluxResponseWriter(exchange.getResponse(), msg, HttpStatus.UNAUTHORIZED);
    }

    /**
     * 获取缓存key
     */
    private String getTokenKey(String token)
    {
        return CacheConstants.LOGIN_TOKEN_KEY + token;
    }

    /**
     * 获取请求token
     */
    private String getToken(ServerHttpRequest request)
    {
        String token = request.getHeaders().getFirst(SecurityConstants.AUTHORIZATION_HEADER);
        // 如果前端设置了令牌前缀，则裁剪掉前缀
        if (StringUtils.isNotEmpty(token) && token.startsWith(TokenConstants.PREFIX))
        {
            token = token.replaceFirst(TokenConstants.PREFIX, StringUtils.EMPTY);
        }
        return token;
    }

    @Override
    public int getOrder()
    {
        return -200;
    }

    private static final List<HttpMessageReader<?>> messageReaders = HandlerStrategies.withDefaults().messageReaders();

    private Mono<Void> openApiAcl(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        OpenApiAclHeaders acl = getAclHeaders(request.getHeaders());
        if (StringUtils.isEmpty(acl.getAccesskey())) {
            return unauthorizedResponse(exchange, "缺少accessKey");
        }
        HashMap<String, String> map = redisService.getCacheObject("openapi:acl:" + acl.getAccesskey());
        if (map == null) {
            return unauthorizedResponse(exchange, "无效的accessKey");
        }
        if (StringUtils.isEmpty(map.get("status")) || !map.get("status").equals("0")) {
            return unauthorizedResponse(exchange, "accessKey状态异常");
        }

        if (request.getMethodValue().equals("POST")) {
            return DataBufferUtils.join(request.getBody()).defaultIfEmpty(exchange.getResponse().bufferFactory().allocateBuffer(0)).flatMap(dataBuffer -> {
                if (dataBuffer.readableByteCount() == 0) {
                    DataBufferUtils.release(dataBuffer);
                    String contentmd5 = toMD5Base64("");
                    if (!contentmd5.equals(acl.getContentmd5())) {
                        return unauthorizedResponse(exchange, "conmentmd5校验失败");
                    }
                    if (!calculateHMAC(map.get("secretKey"), contentmd5 + "\n" + acl.getRequestdate()).equals(acl.getHmac())) {
                        return unauthorizedResponse(exchange, "hmac校验失败");
                    }
                    ServerHttpRequest.Builder mutate = request.mutate();
                    addHeader(mutate, SecurityConstants.USER_KEY, map.get("accessKey"));
                    addHeader(mutate, SecurityConstants.DETAILS_USER_ID, map.get("id"));
                    addHeader(mutate, SecurityConstants.DETAILS_USERNAME, map.get("name"));
                    return chain.filter(exchange.mutate().request(mutate.build()).build());
                } else {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    TreeMap treeMap = JSONObject.parseObject(new String(bytes), TreeMap.class);
                    StringBuilder content = new StringBuilder();
                    treeMap.forEach((k, v) -> {
                        log.info(v.toString());
                        content.append(v).append("\n");
                    });
                    content.delete(content.length() - 1, content.length());
                    String contentmd5 = toMD5Base64(content.toString());
                    if (!contentmd5.equals(acl.getContentmd5())) {
                        return unauthorizedResponse(exchange, "conmentmd5校验失败");
                    }
                    if (!calculateHMAC(map.get("secretKey"), contentmd5 + "\n" + acl.getRequestdate()).equals(acl.getHmac())) {
                        return unauthorizedResponse(exchange, "hmac校验失败");
                    }
                    ServerHttpRequestDecorator mutatedRequest = new ServerHttpRequestDecorator(request) {
                        @Override
                        public Flux<DataBuffer> getBody() {
                            return Flux.defer(() -> {
                                DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
                                DataBufferUtils.retain(buffer);
                                return Mono.just(buffer).doFinally(signalType -> {
                                    DataBufferUtils.release(buffer);
                                });
                            });
                        }
                    };
                    ServerHttpRequest.Builder mutate = mutatedRequest.mutate();
                    addHeader(mutate, SecurityConstants.USER_KEY, map.get("accessKey"));
                    addHeader(mutate, SecurityConstants.DETAILS_USER_ID, map.get("id"));
                    addHeader(mutate, SecurityConstants.DETAILS_USERNAME, map.get("name"));
                    ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();
                    return ServerRequest.create(mutatedExchange, messageReaders).bodyToMono(String.class)
                            .then(chain.filter(mutatedExchange));
                }
            });
        } else if (request.getMethodValue().equals("GET")) {
            StringBuilder content = new StringBuilder();
            MultiValueMap<String, String> params = request.getQueryParams();
            TreeMap<String, String> treeMap = new TreeMap<>();
            params.forEach((k, v) -> {
                treeMap.put(k, v.get(0));
            });
            treeMap.forEach((k, v) -> {
                content.append(v).append("\n");
            });
            if (content.length() > 0) {
                content.delete(content.length() - 1, content.length());
            }

            String contentmd5 = toMD5Base64(content.toString());
            if (!contentmd5.equals(acl.getContentmd5())) {
                return unauthorizedResponse(exchange, "conmentmd5校验失败");
            }
            if (!calculateHMAC(map.get("secretKey"), contentmd5 + "\n" + acl.getRequestdate()).equals(acl.getHmac())) {
                return unauthorizedResponse(exchange, "hmac校验失败");
            }
            ServerHttpRequest.Builder mutate = request.mutate();
            addHeader(mutate, SecurityConstants.USER_KEY, map.get("accessKey"));
            addHeader(mutate, SecurityConstants.DETAILS_USER_ID, map.get("id"));
            addHeader(mutate, SecurityConstants.DETAILS_USERNAME, map.get("name"));
            return chain.filter(exchange.mutate().request(mutate.build()).build());
        } else {
            return unauthorizedResponse(exchange, "不支持的请求方式");
        }
    }

    private OpenApiAclHeaders getAclHeaders(HttpHeaders headers) {
        OpenApiAclHeaders acl = new OpenApiAclHeaders();
        acl.setAccesskey(headers.getFirst("accesskey"));
        acl.setHmac(headers.getFirst("hmac"));
        acl.setRequestdate(headers.getFirst("requestdate"));
        acl.setContentmd5(headers.getFirst("contentmd5"));
        return acl;
    }

    //contentmd5计算方法
    private static String toMD5Base64(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(input.getBytes());
            byte[] digest = md.digest();
            return new String(Base64.encodeBase64(digest));
        } catch (Exception e) {
            throw new ServiceException("contentmd5计算出错：" + e.getMessage(), 401);
        }
    }

    //hmac计算方法
    private static String calculateHMAC(String secret, String data) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(secretKeySpec);
            byte[] rawHmac = mac.doFinal(data.getBytes());
            return new String(Base64.encodeBase64(rawHmac));
        } catch (Exception e) {
            throw new ServiceException("hmac计算出错：" + e.getMessage(), 401);
        }
    }
}