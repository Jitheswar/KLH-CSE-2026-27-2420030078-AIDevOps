# Contribution and Submission Norms

This project must comply with the KLH GitHub Submission Norms for the full duration of the project.
The rules below are binding on every team member.

## Individual Commits

Every team member must commit using their own GitHub account.
Bulk uploads by a single member on behalf of others are not accepted.
Each member should clone the repository and push directly from their own authenticated account.

## Commit Frequency

Maintain progressive commits throughout the project.
Each team member must make at least one meaningful commit per week.
Empty or placeholder commits do not count.

## Phase Tagging

Each phase deliverable must be tagged in git once that phase is actually complete.
Use the following tag names:

- `review-1`
- `review-2`
- `final`

Example: `git tag -a review-1 -m "Review 1 submission" && git push origin review-1`

## Repository Access

Repository access must be granted to the Supervisor and the Course Coordinator.
Access must remain in place until the final project evaluation is completed.

## Security

Do not upload credentials, API keys, licensed datasets, or confidential institutional data to this repository.
See `.gitignore` for patterns that are excluded by default.
If a dataset cannot be shared publicly, document its source in `data/README.md` instead of committing it.

## Repository Identity

Once the repository URL has been recorded with the course, the repository must not be renamed or transferred without written consent from the Course Coordinator.
