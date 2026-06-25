# Native libraries

Place the compiled and patched `.so` files here:

```
arm64-v8a/libsecure_android_vm.so
armeabi-v7a/libsecure_android_vm.so
x86_64/libsecure_android_vm.so
```

Build with (from the library root):

```bash
cargo ndk \
    -t arm64-v8a \
    -t armeabi-v7a \
    -t x86_64 \
    -o android-app/app/src/main/jniLibs \
    build --release \
    --features jni,enforce_patch,enforce_embed_secret,enforce_codesign_key
```

Then embed the firmware secret into each .so:

```bash
for ABI in arm64-v8a armeabi-v7a x86_64; do
    cargo run --bin patch_so -- \
        android-app/app/src/main/jniLibs/$ABI/libsecure_android_vm.so \
        $FIRMWARE_SECRET_HEX
done
```

Do NOT commit `.so` files to version control — distribute them through
your CI/CD artifact pipeline.
