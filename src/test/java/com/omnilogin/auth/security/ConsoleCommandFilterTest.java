package com.omnilogin.auth.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ConsoleCommandFilterTest {

    @Test
    void redactsSensitiveAuthCommandsAndDegradesGracefullyWithoutLog4jCore() {
        assertEquals("/login [REDACTED]", ConsoleCommandFilter.redactCommandLine("/login MySecret123!"));
        assertEquals("/register [REDACTED]", ConsoleCommandFilter.redactCommandLine("/register Pass1 Pass1"));
        assertEquals("/changepassword [REDACTED]", ConsoleCommandFilter.redactCommandLine("/changepassword Old New"));
        assertEquals("/help", ConsoleCommandFilter.redactCommandLine("/help"));

        ConsoleCommandFilter filter = new ConsoleCommandFilter();
        assertDoesNotThrow(() -> filter.setActive(true));
        assertDoesNotThrow(filter::shutdown);
    }
}
