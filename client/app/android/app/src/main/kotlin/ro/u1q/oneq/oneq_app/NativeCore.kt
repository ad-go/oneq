package ro.u1q.oneq.oneq_app

/** JNI bridge to the Rust core (see core/src/ffi.rs, module jni_api). The same library is also opened by dart:ffi. */
object NativeCore {
    init {
        System.loadLibrary("oneq_core")
    }

    external fun prepare(configJson: String): Int
    external fun run(fd: Int): Int
    external fun stop()
    external fun status(): String
    external fun lastError(): String
}
