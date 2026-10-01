package com.github.lisama569.threatdetectionenginejava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * @author Vincent
 * @version 1.0
 */
@SpringBootTest
@TestPropertySource(properties = "engine.state-dir=target/test-state/application-tests")
public class ApplicationTests {
    @Test
    public void contentLoad() {
    }
}
