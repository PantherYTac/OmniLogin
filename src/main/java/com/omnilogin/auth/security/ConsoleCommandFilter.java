package com.omnilogin.auth.security;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.filter.AbstractFilter;
import org.apache.logging.log4j.message.Message;

import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/**
 * Prevents plaintext passwords entered via {@code /login}, {@code /register},
 * and {@code /changepassword} from appearing in server console logs.
 */
public final class ConsoleCommandFilter {

    private static final List<String> SENSITIVE_PREFIXES = List.of(
            "issued server command: /login ",
            "issued server command: /l ",
            "issued server command: /register ",
            "issued server command: /reg ",
            "issued server command: /changepassword ",
            "issued server command: /changepass ",
            "issued server command: /cp ",
            "issued server command: /passwd ",
            "issued server command: /omnilogin:login ",
            "issued server command: /omnilogin:register ",
            "issued server command: /omnilogin:changepassword "
    );

    private static final Pattern REDACT_PATTERN = Pattern.compile(
            "(?i)^/(?:omnilogin:)?(login|l|register|reg|changepassword|changepass|cp|passwd)\\s+.*$"
    );

    private final AtomicBoolean active = new AtomicBoolean(false);
    private volatile boolean registered;

    public void setActive(boolean active) {
        this.active.set(active);
        if (active && !registered) {
            registered = tryRegister();
        }
    }

    public void shutdown() {
        this.active.set(false);
    }

    private boolean tryRegister() {
        try {
            Class.forName("org.apache.logging.log4j.core.filter.AbstractFilter");
            return Log4jCoreHook.attach(active);
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static String redactCommandLine(String rawCommand) {
        if (rawCommand == null) {
            return "";
        }
        return REDACT_PATTERN.matcher(rawCommand).replaceFirst("/$1 [REDACTED]");
    }

    private static final class Log4jCoreHook {
        private Log4jCoreHook() {
        }

        static boolean attach(AtomicBoolean activeFlag) {
            if (!(LogManager.getRootLogger() instanceof Logger rootLogger)) {
                return false;
            }
            AbstractFilter filter = new AbstractFilter() {
                @Override
                public Result filter(LogEvent event) {
                    return evaluate(event != null && event.getMessage() != null
                            ? event.getMessage().getFormattedMessage()
                            : null);
                }

                @Override
                public Result filter(Logger logger, Level level, Marker marker, Message msg, Throwable t) {
                    return evaluate(msg != null ? msg.getFormattedMessage() : null);
                }

                @Override
                public Result filter(Logger logger, Level level, Marker marker, String msg, Object... params) {
                    return evaluate(msg);
                }

                @Override
                public Result filter(Logger logger, Level level, Marker marker, Object msg, Throwable t) {
                    return evaluate(msg != null ? msg.toString() : null);
                }

                private Result evaluate(String message) {
                    if (!activeFlag.get() || message == null) {
                        return Result.NEUTRAL;
                    }
                    String lower = message.toLowerCase(Locale.ROOT);
                    for (String prefix : SENSITIVE_PREFIXES) {
                        if (lower.contains(prefix)) {
                            return Result.DENY;
                        }
                    }
                    return Result.NEUTRAL;
                }
            };
            filter.start();
            rootLogger.addFilter(filter);
            return true;
        }
    }
}
