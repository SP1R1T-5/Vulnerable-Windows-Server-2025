# Risk register — template (WP10)

One row per finding. Keep it as a spreadsheet in real use; the columns are what
matter. Likelihood and impact are **judgements you must defend**, not facts — the
rationale column is the part being graded.

| Risk ID | Finding ID | Description | Likelihood (1-5) | Impact (1-5) | Score | Rationale for the rating | Owner | Treatment | Target date | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| R-001 | | | | | | | | Mitigate / Accept / Transfer / Avoid | | Open |

**Notes on using this honestly:**

- **Score is not a decision.** A 25 you cannot fix this quarter still gets
  accepted, with a rationale. A 6 that takes ten minutes gets fixed.
- **Likelihood is about this environment**, not the internet in general. "SMB
  relay is common" is not a rationale; "signing is off and thirty hostile hosts
  share this subnet" is.
- **Owner is a person**, not a team. Teams do not remember.
- Every row with Treatment = Accept needs a matching
  [risk acceptance](risk-acceptance.md).
