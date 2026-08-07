plugins {
    kotlin("multiplatform") version "2.1.0"
    kotlin("plugin.serialization") version "2.1.0"
}

kotlin {
    // JVM only for now. The Android target needs JDK 17+ for AGP 8.x; adding it
    // later is a source-set addition, not a restructuring, because everything
    // that matters already lives in commonMain.
    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "11"
        }
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit5"))
                runtimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.2")
            }
        }
    }
}

// The golden vectors are the single source shared with the Python reference
// implementation (ADR-0008). They are read from the repository rather than
// copied, so the two suites can never drift onto different files.
tasks.withType<Test>().configureEach {
    systemProperty(
        "passweird.vectors",
        rootProject.projectDir.parentFile.resolve("tests/vectors/derivation-v1.json").absolutePath,
    )
    testLogging {
        events("passed", "failed", "skipped")
    }
}
