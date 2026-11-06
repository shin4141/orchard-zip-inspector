# Release decision — MIT applied; v0.1 published

**As-of: 2026-11-06 JST.** The maintainer selected **MIT** for the standalone Orchard ZIP Inspector v0.1 release candidate, with the copyright notice **Copyright (c) 2026 shin4141**. See [LICENSE](LICENSE).

## Scope and rights

The MIT license applies to the files distributed in this repository, to the extent the licensing copyright holder owns the rights. It permits use, modification, redistribution and commercial use, provided the notice is retained. It does not have the express patent-license provision found in Apache-2.0. The license choice is not a patent-clearance opinion.

The prior source-history review identified one project-owner account as recorded author, found no bundled third-party implementation source and no conflicting license notices. However, employment, assignment, possible co-ownership and outside patent rights have **not** been independently verified. The requested public-facing copyright name is a handle, not a guarantee of anonymity or a legal-title determination.

This license **does not** apply to the separate private Orchard Mac app (B), Linux VM/worker (A), SiriusA, other Decision-OS research or contents of the private source repository.

## Why MIT, not Apache-2.0

MIT was selected as a short permissive license for the small, reproducible developer experiment. Apache-2.0 would add explicit contributor patent terms and redistribution duties. The maintainer chose broad adoption of this narrow v0.1 over preserving exclusivity in the released scanner code. Existing permissions for copies released under MIT generally cannot be withdrawn later.

Reference: [MIT](https://opensource.org/license/mit) and [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).

## Shipped material and verification

The release candidate includes standard-library-only Python source, tests, synthetic ZIPs, generator, example reports, and documentation; no third-party package, interpreter, source bundle or real user archive is shipped. [REPRODUCIBILITY.json](REPRODUCIBILITY.json) records the verified clean-environment tests; [REVIEW.md](REVIEW.md) records the disclosure/scope review.

The v0.1 tool is experimental, not a sandbox, malware scanner, or guarantee that an archive is safe. A result of NOT_DETECTED or CAP cannot authorize execution or opening of the archive.

## Publication status and remaining scope

**Current status (2026-11-06 JST): PUBLIC.** Following the MIT licensing decision, Shin separately approved publishing this standalone repository, and its visibility was changed to public. The prior private/HOLD gate is historical and no longer describes this repository's current visibility. **No social posts or separate promotional announcements were authorized or performed as part of this update.** Do not add A/B, other inventions, or private material to this release. Public availability of v0.1 does not qualify real-world ZIP safety, the Mac app, or VM integration.
