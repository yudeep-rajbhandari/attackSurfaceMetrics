package com.yudeep.attacksurface.entity;

public class CVEScore {
    String accessComplexity;
    String authentication;

    public CVEScore(String accessComplexity, String authentication) {
        this.accessComplexity = accessComplexity;
        this.authentication = authentication;
    }

    public String getAccessComplexity() {
        return accessComplexity;
    }

    public void setAccessComplexity(String accessComplexity) {
        this.accessComplexity = accessComplexity;
    }

    public String getAuthentication() {
        return authentication;
    }

    public void setAuthentication(String authentication) {
        this.authentication = authentication;
    }
}
