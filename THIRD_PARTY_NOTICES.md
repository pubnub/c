# Third-Party Notices

The PubNub C SDK incorporates or, at build time, fetches the third-party
components listed below. Each is used under the terms of its respective
license. Versions correspond to the commit SHAs pinned in the SDK build
configuration (`cmake/dependencies.cmake` and the per-target `CMakeLists.txt`
files that resolve optional backends).

This file is provided to satisfy the attribution requirements of the licenses
below. It does not modify those licenses; the authoritative terms are the
LICENSE / COPYING files distributed with each project's source.

---

## cJSON

- **Version:** v1.7.18 (commit `acc76239bee01d8e9c858ae2cab296704e52d916`)
- **Role:** Default JSON serialization backend (hosted profiles).
- **License:** MIT License
- **SPDX-License-Identifier:** `MIT`
- **Repository:** https://github.com/DaveGamble/cJSON

```
Copyright (c) 2009-2017 Dave Gamble and cJSON contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## jsmn

- **Version:** v1.1.0 (commit `fdcef3ebf886fa210d14956d3c068a653e76a24e`)
- **Role:** Minimal JSON tokenizer serialization backend (embedded profile).
- **License:** MIT License
- **SPDX-License-Identifier:** `MIT`
- **Repository:** https://github.com/zserge/jsmn

```
Copyright (c) 2010 Serge A. Zaitsev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## miniz

- **Version:** 3.1.2 (commit `77d0dce8627735138c51770d1799a1ef48f2117d`)
- **Role:** Inflate-only (tinfl) subset for embedded HTTP response decompression.
- **License:** MIT License
- **SPDX-License-Identifier:** `MIT`
- **Repository:** https://github.com/richgel999/miniz

```
Copyright 2013-2014 RAD Game Tools and Valve Software
Copyright 2010-2014 Rich Geldreich and Tenacious Software LLC

All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## zlib

- **Version:** v1.3.1 (commit `51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf`)
- **Role:** Request/response compression backend (fetched only when a system
  zlib is not found).
- **License:** zlib License
- **SPDX-License-Identifier:** `Zlib`
- **Repository:** https://github.com/madler/zlib

```
(C) 1995-2024 Jean-loup Gailly and Mark Adler

This software is provided 'as-is', without any express or implied
warranty.  In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.

Jean-loup Gailly        Mark Adler
jloup@gzip.org          madler@alumni.caltech.edu
```

---

## cmocka

- **Version:** cmocka-2.0.2 (commit `fefa2b8a023121f7235e18ed17249e4012dd144f`)
- **Role:** Unit-test framework. **Test/development only** — not linked into
  the distributed SDK library or into consumer applications.
- **License:** Apache License 2.0
- **SPDX-License-Identifier:** `Apache-2.0`
- **Repository:** https://gitlab.com/cmocka/cmocka

```
Copyright 2008 Google Inc.
Copyright 2014-2022 Andreas Schneider <asn@cryptomilk.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## Mbed TLS

- **Version:** v3.6.3 (archive
  `SHA256=e69c4c13377e89b9d696006ef9c8258e3be75b6dbd464cfd573360482b1a1f4e`)
- **Role:** Optional TLS/crypto backend for the socket transport (fetched only
  when a system Mbed TLS is not found).
- **License:** Apache License 2.0 OR GPL-2.0-or-later (dual-licensed; the SDK
  uses it under Apache-2.0).
- **SPDX-License-Identifier:** `Apache-2.0 OR GPL-2.0-or-later`
- **Repository:** https://github.com/Mbed-TLS/mbedtls

```
Copyright The Mbed TLS Contributors

Mbed TLS files are provided under a dual Apache-2.0 OR GPL-2.0-or-later
license. Users may choose which of these licenses they take the code under.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use these files except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## curl / libcurl

- **Version:** 8.12.0 (release tag `curl-8_12_0`)
- **Role:** Optional HTTP transport backend (fetched only when a system
  libcurl is not found).
- **License:** curl License (MIT/X-derivate)
- **SPDX-License-Identifier:** `curl`
- **Repository:** https://github.com/curl/curl

```
COPYRIGHT AND PERMISSION NOTICE

Copyright (c) 1996 - 2025, Daniel Stenberg, <daniel@haxx.se>, and many
contributors, see the THANKS file.

All rights reserved.

Permission to use, copy, modify, and distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall not
be used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization of the copyright holder.
```

---

## OpenSSL (system dependency — not distributed)

OpenSSL is resolved via `find_package(OpenSSL)` and linked from the host
system when the OpenSSL crypto/TLS backend is selected. It is **not** fetched
or redistributed with this SDK; it is listed here for completeness because the
SDK links against it.

- **Role:** Optional TLS/crypto backend (system-provided).
- **License:** Apache License 2.0 (OpenSSL 3.x).
- **SPDX-License-Identifier:** `Apache-2.0`
- **Repository:** https://github.com/openssl/openssl
- **Copyright:** Copyright (c) 1998-2024 The OpenSSL Project Authors. All
  Rights Reserved.
