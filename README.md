# mdl-verifier

A cross-platform ISO 18013-5 mDL verifier.

Features:
- [x] NFC Static Handover Engagement
- [x] NFC Negotiated Handover Engagement
- [x] QR Engagement
- [x] BLE Peripheral Server Retrieval
- [ ] BLE Central Client Retrieval
- [x] Verification

## Running

A sample app is provded in bin/verifier.rs, it requires a serial barcode scanner
and optionally an NFC reader compatible with libnfc.
