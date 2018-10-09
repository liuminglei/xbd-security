package com.xbd.xbdframework.security.access.intercept;

import com.xbd.xbdframework.security.service.ResourcesLoaderService;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.Map.Entry;

public class XbdFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private ResourcesLoaderService resourcesLoaderService;

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        HttpServletRequest request = ((FilterInvocation) object).getRequest();
        Iterator<Entry<RequestMatcher, Collection<ConfigAttribute>>> var3 = this.getRequestMap().entrySet().iterator();

        Entry<RequestMatcher, Collection<ConfigAttribute>> entry;
        do {
            if (!var3.hasNext()) {
                return null;
            }

            entry = var3.next();
        } while (!entry.getKey().matches(request));

        return entry.getValue();
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        HashSet<ConfigAttribute> allAttributes = new HashSet<>();
        Iterator<Entry<RequestMatcher, Collection<ConfigAttribute>>> var2 = this.getRequestMap().entrySet().iterator();

        while (var2.hasNext()) {
            Entry<RequestMatcher, Collection<ConfigAttribute>> entry = var2.next();
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    private Map<RequestMatcher, Collection<ConfigAttribute>> getRequestMap() {

        Map<RequestMatcher, Collection<ConfigAttribute>> requestMap = new HashMap<>();

        Map<String, Collection<String>> loadResources = this.resourcesLoaderService.loadResources();

        for (Map.Entry<String, Collection<String>> entry : loadResources.entrySet()) {
            Collection<ConfigAttribute> c_roles = new ArrayList<>();

            for (String role : entry.getValue()) {
                c_roles.add(new SecurityConfig("ROLE_" + role));
            }

            RequestMatcher r_url = new AntPathRequestMatcher(entry.getKey());

            requestMap.put(r_url, c_roles);
        }

        return requestMap;
    }

    public ResourcesLoaderService getResourcesLoaderService() {
        return resourcesLoaderService;
    }

    public void setResourcesLoaderService(ResourcesLoaderService resourcesLoaderService) {
        this.resourcesLoaderService = resourcesLoaderService;
    }
}
