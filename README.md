# KeyMint/Rust

This repo holds work in progress for a Rust implementation of Android's KeyMint HAL.

## Repo Structure

The codebase is divided as follows. Only the crates in **bold** are expected to be used in Android; the remainder are
conveniences to allow development outside of Android.

| Subdir           | Crate Name       | `std`?                 | Description                                           |
|------------------|------------------|------------------------|-------------------------------------------------------|
| **`derive`**     | `kmr-derive`     | Yes (build-only)       | Proc macros for deriving the `AsCborValue` trait      |
| **`common`**     | `kmr-common`     | No                     | Common code used throughout KeyMint/Rust              |
| **`hal`**        | `kmr-hal`        | Yes                    | HAL service implementation                            |
| **`boringssl`**  | `kmr-boringssl`  | Yes                    | Boring/OpenSSL-based implementations of crypto traits |
| `tests`          | `kmr-tests`      |                        | Tests and test infrastructure                         |
| **`ta`**         | `kmr-ta`         | No                     | TA implementation                                     |
| `ta-main`        | `kmr-ta`         | Yes                    | TA implementation using TCP                           |
