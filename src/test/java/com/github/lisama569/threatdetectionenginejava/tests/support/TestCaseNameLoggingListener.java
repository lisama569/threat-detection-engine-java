package com.github.lisama569.threatdetectionenginejava.tests.support;

import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 全局测试监听器（经 ServiceLoader 自动注册）：在测试日志中明确打印每个用例的
 * “开始 / 通过 / 失败”，配合逐条事件判定日志与重启前后窗口快照，
 * 可直接从日志看出各用例名称、通过情况与判定依据。
 */
public class TestCaseNameLoggingListener implements TestExecutionListener {

    private static final Logger log = LoggerFactory.getLogger("TEST-CASE");

    @Override
    public void executionStarted(TestIdentifier testIdentifier) {
        if (testIdentifier.isTest()) {
            log.info(">>>>> 用例开始: {} [{}]", testIdentifier.getDisplayName(),
                    testIdentifier.getUniqueId().replace('/', ' '));
        }
    }

    @Override
    public void executionFinished(TestIdentifier testIdentifier, TestExecutionResult result) {
        if (testIdentifier.isTest()) {
            String status = switch (result.getStatus()) {
                case SUCCESSFUL -> "PASSED ✅";
                case FAILED -> "FAILED ❌";
                case ABORTED -> "ABORTED ⚠️";
            };
            if (result.getThrowable().isPresent()) {
                log.error("<<<<< 用例{}: {} 原因={}", status, testIdentifier.getDisplayName(),
                        result.getThrowable().get().toString());
            } else {
                log.info("<<<<< 用例{}: {}", status, testIdentifier.getDisplayName());
            }
        }
    }
}
