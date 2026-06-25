# ══════════════════════════════════════════════════════════════════════════════
#  proguard-rules.pro — SecureVm Demo
# ══════════════════════════════════════════════════════════════════════════════
#
#  WHY THESE RULES EXIST
#  ─────────────────────
#  R8 (Android's shrinker/obfuscator) renames classes and methods to short
#  names (a, b, c …) for size and obfuscation.  JNI functions are resolved
#  BY NAME at load time — the native .so has hard-coded strings like:
#
#      Java_com_example_securevm_SecureVm_nativeStart
#
#  If R8 renames the `SecureVm` class or any `native` method, the JNI
#  linkage silently fails (UnsatisfiedLinkError at runtime).  The rules
#  below prevent that.
# ══════════════════════════════════════════════════════════════════════════════

# Keep the SecureVm wrapper class and all its members.
# The `native` methods MUST keep their exact names; R8 must not rename them.
-keep class com.example.securevm.SecureVm {
    *;
}

# Keep the Application subclass (referenced by name in AndroidManifest.xml).
-keep class com.example.securevm.demo.DemoApplication { *; }

# Keep MainActivity (referenced by name in AndroidManifest.xml).
-keep class com.example.securevm.demo.MainActivity { *; }

# Standard Android rules — keep activities, services, receivers, providers.
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service

# Suppress notes about reflection used by AppCompat internals.
-dontnote androidx.**
-dontnote android.support.**
