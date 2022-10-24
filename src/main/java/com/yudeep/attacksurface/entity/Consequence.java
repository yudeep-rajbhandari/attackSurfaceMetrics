package com.yudeep.attacksurface.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class Consequence {
    @JsonProperty("Scope")
    private List<String> scope;
    @JsonProperty("Impact")
    private List<String> impact;
    @JsonProperty("Note")
    private String note;

    public List<String> getScope() {
        return scope;
    }

    public void setScope(List<String> scope) {
        this.scope = scope;
    }

    public List<String> getImpact() {
        return impact;
    }

    public void setImpact(List<String> impact) {
        this.impact = impact;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note;
    }
}
