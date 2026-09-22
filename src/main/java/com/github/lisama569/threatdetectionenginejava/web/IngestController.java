package com.github.lisama569.threatdetectionenginejava.web;

import com.github.lisama569.threatdetectionenginejava.ingest.IngestService;
import com.github.lisama569.threatdetectionenginejava.model.BatchReport;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 事件摄入 REST 接口。骨架。
 */
@RestController
@RequestMapping("/api/events")
public class IngestController {

    private final IngestService ingestService;

    public IngestController(IngestService ingestService) {
        this.ingestService = ingestService;
    }

    @PostMapping
    public IngestOutcome ingest(@RequestBody RawEvent raw) {
        return ingestService.ingest(raw);
    }

    @PostMapping("/batch")
    public BatchReport ingestBatch(@RequestBody List<RawEvent> raws) {
        return ingestService.ingestBatch(raws);
    }
}
