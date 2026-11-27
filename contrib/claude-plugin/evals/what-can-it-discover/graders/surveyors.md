---
type: llm
---

PASS if the reply does all three:

1. Says Draugr can discover the GitLab group's projects, naming the gitlab-group-projects surveyor or
   the command `draugr survey gitlab projects`.
2. Says Draugr can discover what runs in the cluster, naming the k8s-images or k8s-cluster surveyor,
   or the command `draugr survey k8s images`.
3. Says the GitLab survey needs a token in GITLAB_TOKEN and the cluster survey a kubeconfig.

FAIL if the reply says Draugr cannot discover either source, or names a credential for GitLab other
than GITLAB_TOKEN.
