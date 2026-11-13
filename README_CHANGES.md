# Changes in vscpl2drv-logger

Every change that goes into a release is listed here, newest release first.
Add each change under **Unreleased** when it is made. When a release is
tagged, rename **Unreleased** to the version and date, and start a new
**Unreleased** section above it.

## Unreleased

- Replace the third-party git submodules (vscp, spdlog, json, Mustache, maddy, crypto-algorithms) with CMake FetchContent (same pinned commits)
- Add scripts/download-artifacts.sh to download and verify the newest CI build artifacts
- CI writes a SHA256SUMS-<artifact> checksum file into every uploaded build artifact
- Changed to cmake (e20ff86)
- Changed driver model (48dea43)
- Updated repository intro picture (632bf59)
- Updated main readme (0fafd1a)
- Added missing files to docs (5cb9332)

## v15.1.0 - 2025-11-12

- Updated install script so license is displayed (f979a8e)
- Updated docs (40460c2)
- Console and file logger now can have different log levels (163b91e)
- Added preset file (9842b53)
- Fixed build scripts (a48c0fc)
- Fixed windows build (762f879)
- Fixed cross compile semaphore issue (ca0ec64)
- Rearranged logger obj code (91e617f)
- Fixed windows/linux includes files issues (9520b11)
- Fixed linux only compiler flags (d912f93)
- Updated github action files to later valid code (08e4345)
- Added new doc sceleton (bae2630)
- Updated project to new model (2c03a73)
- Fixed logger consoleLogPattern (cae3029)
- Added abh compile flags (681df7d)
- spdlog and json lib is now submodules (1c2bfd8)
- Updated dependencies (d289163)
