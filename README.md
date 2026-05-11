# embedded-tls-hardware

(WIP) Hardware acceleration for embedded-tls on many chips. See https://github.com/drogue-iot/embedded-tls/issues/123 .

## ToDo

- [x] Impl `HwAes128GcmSha256` on top of [`esp-hal`](https://github.com/esp-rs/esp-hal).
- [ ] Impl RSA/ED25516 based on `esp-hal`.
- [ ] More chips.
