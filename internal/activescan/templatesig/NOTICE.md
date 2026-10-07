# Attribution — signatures.json

`signatures.json` is a normalized, curated derivative of the
[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) project
by ProjectDiscovery, used under the MIT License.

- Source: `github.com/projectdiscovery/nuclei-templates`
- License: MIT (permits modification and redistribution with this notice)
- Generated at design time by `tools/nucleigen` from commit
  `58670555f97912d95733b509e08061785f66e5e5` (subtrees `http/exposures`,
  `http/misconfiguration`, `http/exposed-panels`).

Each entry records the originating template id (`nucleiId`) and its path within
the checkout (`source`). Only templates whose whole logic fits Joro's supported
HTTP matcher subset were converted; the rest were dropped (see the converter's
skip census). The dataset is regenerated, never hand-edited.

The MIT license text accompanies the ProjectDiscovery repository; this derivative
is distributed under the same terms.
