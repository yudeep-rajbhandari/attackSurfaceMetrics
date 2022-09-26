package com.yudeep.attacksurface.entity;

public class SonarRules {
private String key;
private String name;

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getHtmlDesc() {
        return htmlDesc;
    }

    public void setHtmlDesc(String htmlDesc) {
        this.htmlDesc = htmlDesc;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    private String htmlDesc;
private String severity;
}
