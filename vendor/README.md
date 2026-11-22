# RandomX source provenance

Source: https://github.com/tevador/RandomX
Tag: v2.0.1
Commit: aaafe71322df6602c21a5c72937ac284724ae561
License: BSD-3-Clause; retained in randomx/LICENSE. Component notices are retained.
The vcxproj/h2inc.ps1 translator carries its own MIT notice.

Copied without source changes from the inspected upstream checkout: src/,
vcxproj/, CMakeLists.txt and LICENSE. The JSON manifest records exact SHA-256
checksums of this vendored snapshot. Verify using `python tools/verify_vendor.py`.

Builds copy these inputs into Cargo OUT_DIR because upstream Windows CMake
generates assembly includes inside its source tree. Neither the research checkout
nor this vendored snapshot is modified. Only the randomx static-library target is
built; upstream benchmark and miner programs are not built or run.

The wrapper pins the v2 flag independently of the source release. Platform
support is currently restricted to native x86_64 Windows MSVC and Linux GNU
builds; runtime agreement on Linux still requires qualification on that platform.
