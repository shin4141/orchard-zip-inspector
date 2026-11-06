# License decision pending

No license has been selected or granted for this release candidate. This document is decision material, not a license. Before public open-source distribution, confirm the rightsholder(s), authority to license all shipped source/tests/docs/synthetic samples, and the copyright notice, then add the chosen `LICENSE`.

The reviewed source history identifies one project-owner account as the recorded author. No third-party implementation source or existing license notice was identified in the extracted files. That review does not establish employment, assignment, or other outside rights. Rightsholder confirmation remains outstanding.

| Candidate | Decision-relevant differences |
|---|---|
| **MIT — suggested for a minimal permissive release** | Short permission notice; redistribution retains the copyright and permission notices. It contains no express patent-license section. [Official MIT text](https://opensource.org/license/mit) |
| **Apache-2.0** | Includes an express contributor patent grant and patent-litigation termination condition; redistribution includes license/notice/change-marking duties, including preservation of applicable NOTICE content. It does not grant trademark permission. [Official Apache-2.0 text](https://www.apache.org/licenses/LICENSE-2.0) |

## Dependencies and shipped material

- Runtime: Python standard library, including `zipfile` and `zlib`. No required pip packages.
- Tests and sample generator also use only the standard library.
- No Python interpreter, standard-library source, zlib binary/source, third-party package, or external project source is bundled. Users supply their Python runtime; its own licensing remains separate.
- Samples contain synthetic documentation, data, and inert script text; reports contain synthetic evidence. No actual secrets, user archives, or live-service responses are shipped.

Remaining decision: confirm the rightsholder/copyright notice and choose one license. Do not label this project MIT/Apache-2.0 until that decision is implemented. See [GitHub's licensing guidance](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository) on unlicensed repositories.
