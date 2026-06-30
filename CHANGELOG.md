# Changelog

## [0.0.2] - 2026-06-30

### CI

- fix(ci): use PAT to bypass branch protection for badge push
- fix(ci): replace git-auto-commit-action with manual PAT push for badge
- fix(ci): remove ruleset bypass, use GITHUB_TOKEN for badge push

### Changes

- Add -pn and -mcn flags for proper-noun and split-column name redaction
- Update README for -pn and -mcn flags
- Add CI workflow, CRAP analysis, and Dependabot
- Fix CI: add missing click dep and handle empty test report
- Fix CI: install click before spacy model download
- Fix Dependabot badge; surface CRAP report in Actions summary
- Update openpyxl requirement from >=3.1 to >=3.1.5
- Update python-docx requirement from >=1.1 to >=1.2.0
- Update spacy requirement from >=3.7 to >=3.8.14
- Add CI reports section and link to run summary in README
- Raise test coverage from 62% to 100%

### Dependencies

- Bump dorny/test-reporter from 1 to 3
- Bump actions/setup-python from 5 to 6
- Bump actions/upload-artifact from 4 to 7
- Bump actions/cache from 4 to 6
- Bump stefanzweifel/git-auto-commit-action from 5 to 7
- Bump odfpy >=1.4.1 and pdfplumber >=0.11.10

### Refactor

- refactor: reduce cyclomatic complexity of process_xlsx and cmd_redact
## [0.0.1] - 2026-06-26

### Changes

- Initial release of pseudo-anonymize
- Rename project from pseudo-anonymize to redact

