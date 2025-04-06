package com.demo.vo;

import lombok.*;

import java.io.Serializable;

@Builder
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ResponseDto implements Serializable {

    private String message;
    private String status;
    private String path;
    private Object data;

    @Getter
    public enum Status {
        STATUS_000("000", "SUCCESS"),
        STATUS_999("999", "ERROR");

        private String code;
        private String message;

        Status(String code, String message) {
            this.code = code;
            this.message = message;
        }
    }
}
