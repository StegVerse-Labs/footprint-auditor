git reset --hard "$GITHUB_SHA"
git clean -fdx
test -z "$(git status --porcelain=v1)"
