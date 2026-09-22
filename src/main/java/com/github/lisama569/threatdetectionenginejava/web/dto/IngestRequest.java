package com.github.lisama569.threatdetectionenginejava.web.dto;

import java.util.Map;

/** REST 摄入请求。 */
public record IngestRequest(String sourceId, String deliveryId, Map<String, Object> payload) {
}
