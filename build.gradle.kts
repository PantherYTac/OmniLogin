plugins {
    java
    id("com.gradleup.shadow") version "9.6.1"
}

group = "com.omnilogin"
version = "0.0.1-alpha"
description = "Production-grade modular authentication plugin for Paper, Spigot, and Purpur"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

repositories {
    mavenCentral()
    maven("https://repo.papermc.io/repository/maven-public/") {
        name = "papermc"
    }
}

dependencies {
    // Paper API (binary-compatible with Paper, Spigot, and Purpur 1.20 - 1.21+)
    compileOnly("io.papermc.paper:paper-api:1.20.4-R0.1-SNAPSHOT")

    // Netty & Log4j APIs provided by the server runtime at execution time
    compileOnly("io.netty:netty-transport:4.1.93.Final")
    compileOnly("io.netty:netty-codec:4.1.93.Final")
    compileOnly("io.netty:netty-buffer:4.1.93.Final")
    compileOnly("org.apache.logging.log4j:log4j-core:2.19.0")

    // Adventure MiniMessage & cross-platform Bukkit/Paper/Spigot audience bridge
    implementation("net.kyori:adventure-api:4.17.0")
    implementation("net.kyori:adventure-text-minimessage:4.17.0")
    implementation("net.kyori:adventure-text-serializer-legacy:4.17.0")
    implementation("net.kyori:adventure-text-serializer-plain:4.17.0")
    implementation("net.kyori:adventure-platform-bukkit:4.3.3")

    // Production password hashing (pure-Java RFC 9106 Argon2id & OpenBSD BCrypt)
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")

    // HikariCP connection pooling and SQLite / MySQL JDBC drivers
    implementation("com.zaxxer:HikariCP:5.1.0") {
        exclude(group = "org.slf4j", module = "slf4j-api")
    }
    implementation("org.xerial:sqlite-jdbc:3.45.2.0")
    implementation("com.mysql:mysql-connector-j:8.3.0")

    // Unit testing
    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("org.mockito:mockito-core:5.11.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.11.0")
    testImplementation("io.papermc.paper:paper-api:1.20.4-R0.1-SNAPSHOT")
    testImplementation("io.netty:netty-transport:4.1.93.Final")
    testImplementation("io.netty:netty-codec:4.1.93.Final")
    testImplementation("io.netty:netty-buffer:4.1.93.Final")
}

tasks {
    withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.release.set(21)
    }

    processResources {
        val props = mapOf(
            "version" to project.version.toString(),
            "description" to project.description.toString()
        )
        inputs.properties(props)
        filteringCharset = "UTF-8"
        filesMatching("plugin.yml") {
            expand(props)
        }
    }

    test {
        useJUnitPlatform()
    }

    shadowJar {
        archiveClassifier.set("")
        archiveBaseName.set("OmniLogin")

        // Relocate shaded libraries to prevent classpath conflicts on Paper/Spigot/Purpur
        relocate("net.kyori", "com.omnilogin.auth.libs.kyori")
        relocate("com.zaxxer.hikari", "com.omnilogin.auth.libs.hikari")
        relocate("org.bouncycastle", "com.omnilogin.auth.libs.bouncycastle")

        // Strip BouncyCastle JCE signature files so relocated shaded JAR loads cleanly
        exclude("META-INF/*.SF")
        exclude("META-INF/*.DSA")
        exclude("META-INF/*.RSA")
        exclude("META-INF/LICENSE*")
        exclude("META-INF/NOTICE*")

        filesMatching("META-INF/services/**") {
            duplicatesStrategy = DuplicatesStrategy.INCLUDE
        }

        mergeServiceFiles()
    }

    build {
        dependsOn(shadowJar)
    }
}
