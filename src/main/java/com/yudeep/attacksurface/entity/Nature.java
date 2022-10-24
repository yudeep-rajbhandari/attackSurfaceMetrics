package com.yudeep.attacksurface.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;

@JsonRootName("attr")
public class Nature {
    @JsonProperty("@_Nature")
    String nature1;

    @JsonProperty("@_CWE_ID")
    String cweID;
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
        return nature1;
    }

    public void setNature(String nature) {
        this.nature1 = nature;
    }

    public String getCWEID() {
        return cweID;
    }

    public void setCWEID(String cweID) {
        this.cweID = cweID;
    }

    public String getViewID() {
        return ViewID;
    }

    public void setViewID(String viewID) {
        ViewID = viewID;
    }

}
