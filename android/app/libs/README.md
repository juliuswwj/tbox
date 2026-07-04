# Generated native library

`tbox.aar` is produced by gomobile and is **not** checked in. Build it from the
repository root before opening/building the Android project:

```sh
make android
```

That runs `gomobile bind` (with the `with_utls` tag, required for REALITY) over
the `./mobile` package plus sing-box's `experimental/libbox`, writing
`tbox.aar` into this directory.
