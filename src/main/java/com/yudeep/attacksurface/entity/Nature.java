package com.yudeep.attacksurface.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;

@JsonRootName("attr")
public class Nature {
    @JsonProperty("@_Nature")
    String Nature;

    @JsonProperty("@_CWE_ID")
    String CWEID;
    @JsonProperty("@_View_ID")
    String ViewID;

    @JsonProperty("@_Ordinal")
    String ordinal;

    public String getOrdinal() {
        return ordinal;
    }

    public void setOrdinal(String ordinal) {
        this.ordinal = ordinal;
    }

    public String getNature() {
        return Nature;
    }

    public void setNature(String nature) {
        Nature = nature;
    }

    public String getCWEID() {
        return CWEID;
    }

    public void setCWEID(String CWEID) {
        this.CWEID = CWEID;
    }

    public String getViewID() {
        return ViewID;
    }

    public void setViewID(String viewID) {
        ViewID = viewID;
    }

}
