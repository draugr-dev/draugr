# GitLab security report schemas

Verbatim copies of GitLab's published schemas, used by `TestGitLabReportsMatchTheirSchema`.

- Source: <https://gitlab.com/gitlab-org/security-products/security-report-schemas>, `dist/`
- Version: **15.2.4**, the version `gitlabSchemaVersion` declares

GitLab rejects a document whose declared version it does not recognise, so these are what stands
behind the format: the tier that renders the result in the Vulnerability Report is Ultimate, and a
schema check is the part that can be proved anywhere.

Refresh both files and `gitlabSchemaVersion` together, and read the diff — a new required field is
a document GitLab will start refusing.
