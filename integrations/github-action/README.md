# Watchtower evals GitHub Action

Pushes prompts from a directory, runs an experiment, prints the table, comments on the pull
request with `GITHUB_TOKEN` and fails the job when a threshold or the baseline comparison fails.

```yaml
- uses: ./integrations/github-action/watchtower-evals
  with:
    api: https://watchtower.example.com
    key: ${{ secrets.WT_API_KEY }}
    project: prj_123
    dataset: support-golden
    prompt: support/answer@staging
    evaluators: accuracy,tone
    fail-under: accuracy=0.8
    baseline: main-latest
    prompts-dir: prompts
```

The job needs `pull-requests: write` for the comment. Exit codes of `wtctl evals run`: 0 pass,
1 threshold or regression failed, 2 infrastructure error. The same commands work in any CI:
`wtctl prompts push|pull --dir prompts/` and `wtctl evals run`. A pytest plugin is not built.
