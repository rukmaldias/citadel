// ══════════════════════════════════════════════════════════════════════════════
//  app/build.gradle.kts
// ══════════════════════════════════════════════════════════════════════════════
//
//  INTEGRATION NOTES
//  ─────────────────
//  1. minSdk 24 (Android 7.0) is the minimum required by the SecureVm library:
//       • APK Signature Scheme v2 is guaranteed (needed for cert extraction).
//       • On API 28+ (Android 9) the library also probes v3 blocks.
//
//  2. The .so files go in:
//       app/src/main/jniLibs/arm64-v8a/libsecure_android_vm.so
//       app/src/main/jniLibs/armeabi-v7a/libsecure_android_vm.so
//       app/src/main/jniLibs/x86_64/libsecure_android_vm.so
//
//     Build them with (from the library root):
//       cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
//           -o android-app/app/src/main/jniLibs \
//           build --release \
//           --features jni,enforce_patch,enforce_embed_secret,enforce_codesign_key
//
//     Then patch each .so:
//       cargo run --bin patch_so -- \
//           android-app/app/src/main/jniLibs/arm64-v8a/libsecure_android_vm.so \
//           $FIRMWARE_SECRET
//
//  3. The three asset files go in:
//       app/src/main/assets/license.bin
//       app/src/main/assets/firmware.bin
//       app/src/main/assets/codesign.bin
//
//     Generate them with:
//       CODESIGN_PRIVATE_KEY=<hex> cargo run \
//           --manifest-path tools/gen_assets/Cargo.toml
//
//  4. ProGuard / R8: see proguard-rules.pro.  JNI entry points must not be
//     renamed or removed; the rules file handles this automatically.
//
// ══════════════════════════════════════════════════════════════════════════════

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace   = "com.example.securevm.demo"
    compileSdk  = 35

    defaultConfig {
        applicationId   = "com.example.securevm.demo"
        minSdk          = 24   // Android 7.0 — minimum for APK Signature Scheme v2
        targetSdk       = 35
        versionCode     = 1
        versionName     = "1.0"

        // INTEGRATION: if you rename the JNI export prefix in jni_api.rs
        // (to match your own package name), update applicationId here to match.
        // The JNI function names are Java_<pkg>_SecureVm_<method> where <pkg>
        // uses underscores instead of dots, e.g. com_example_securevm_SecureVm.
    }

    buildTypes {
        release {
            // Minify + R8 strip unused code.  proguard-rules.pro keeps the
            // JNI entry points and the SecureVm class.
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            // Debug builds: do NOT use the production asset files with
            // firmware_flags=0.  Either:
            //   (a) generate a separate debug licence with firmware_flags=1
            //       to enable the VM trace log, OR
            //   (b) use start() + loadProgram() directly and skip asset verification.
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    // Split the APK by ABI so each device downloads only the .so it needs.
    // This reduces APK size by ~50% for users on arm64-only devices.
    splits {
        abi {
            isEnable     = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = false   // set true if you need a single universal APK
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)

    // No additional dependencies required for the SecureVm library itself —
    // all crypto is in the native .so.  The wrapper (SecureVm.kt) only needs
    // the Android SDK classes already available on device.
}
