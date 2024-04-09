package com.talenthub.auth.tool;

import com.fasterxml.jackson.annotation.JsonAnySetter;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class UrlencodedWriter {
    private final StringBuilder builder = new StringBuilder();

    @JsonAnySetter
    public void write(String key, String value) {
        if (!builder.isEmpty()) {
            builder.append("&");
        }
        builder.append(URLEncoder.encode(key, StandardCharsets.UTF_8)).append("=");

        if (value != null) {
            builder.append(URLEncoder.encode(value,  StandardCharsets.UTF_8));
        }
    }

    @Override
    public String toString(){
        return builder.toString();
    }
}
