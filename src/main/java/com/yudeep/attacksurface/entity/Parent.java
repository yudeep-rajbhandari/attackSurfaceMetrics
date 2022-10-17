package com.yudeep.attacksurface.entity;

import com.fasterxml.jackson.annotation.JsonProperty;


public class Parent {

    @JsonProperty("attr")
    Nature attr;

    public Nature getAttr() {
        return attr;
    }

    public void setAttr(Nature attr) {
        this.attr = attr;
    }

}
