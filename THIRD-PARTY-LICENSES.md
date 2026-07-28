# Third-party licenses

## Hamza Rulepack (`src/main/resources/rulepack/rulepack.json`)

The Hamza Rulepack is **derived from an industry-standard open-source secret-rule
corpus** (the Gitleaks rule set). The rule regexes, entropy thresholds, keywords,
and allowlists in `src/main/resources/rulepack/rulepack.json`, and the parity
corpus under `src/test/resources/scanner/rulepack-corpus/`, are generated from that
upstream project's configuration and reviewed as a versioned artifact. The pack
records the exact upstream commit it was generated from in its own `upstreamRef`
and `upstreamMinVersion` fields.

The upstream project is licensed under the MIT License. Its license and copyright
notice are reproduced in full below, as the MIT License requires when its material
is copied, modified, or redistributed — including in derived and renamed form.

### Gitleaks — MIT License

```
MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Hamza Rulepack — Betterleaks-derived rules (`src/main/resources/rulepack/phase1-active-rules.json`, `localRules`)

The rulepack was extended in 2026-07 with secret-detection rules present in
**Betterleaks** (the Gitleaks successor by the same author) but absent from the
frozen Gitleaks corpus — including AWS secret access keys and modern AI-provider
keys (Cursor, Groq, Mistral, xAI, OpenRouter, DeepSeek, and others). These rules'
regexes, keywords, entropy thresholds, and the true/false-positive corpus samples
under `src/test/resources/scanner/rulepack-corpus/` are generated from Betterleaks'
configuration and sample generators, and reviewed as a versioned artifact. The
import pins the exact upstream commit it was generated from.

Betterleaks is licensed under the MIT License. Its license and copyright notice
are reproduced in full below, as the MIT License requires when its material is
copied, modified, or redistributed — including in derived and renamed form.

### Betterleaks — MIT License

```
MIT License

Copyright (c) 2026 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
