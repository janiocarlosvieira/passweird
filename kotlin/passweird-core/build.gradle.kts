plugins {
    kotlin("multiplatform") version "2.1.0"
    kotlin("plugin.serialization") version "2.1.0"
    id("com.android.library") version "8.7.3"
}

kotlin {
    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "17"
        }
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }

    // Adding Android was a source-set addition, not a restructuring: every
    // derivation already lives in commonMain, and the JVM `actual` for the hash
    // primitives is shared with the desktop target unchanged.
    androidTarget {
        compilations.all {
            kotlinOptions.jvmTarget = "17"
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
            }
        }

        // Android and Desktop are both JVM, so the hash primitives have exactly
        // one `actual`, shared by both. Duplicating them per target would create
        // precisely the divergence the golden vectors exist to prevent - and two
        // copies of a crypto primitive is how they quietly stop matching.
        val jvmCommonMain by creating {
            dependsOn(commonMain)
        }
        val jvmMain by getting {
            dependsOn(jvmCommonMain)
        }
        val androidMain by getting {
            dependsOn(jvmCommonMain)
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

android {
    namespace = "dev.passweird.core"
    compileSdk = 35

    defaultConfig {
        // API 26 covers effectively every device still in use and avoids the
        // desugaring that lower levels would require for java.time APIs.
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
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
