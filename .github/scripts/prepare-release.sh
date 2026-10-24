#!/usr/bin/env bash
# Prepares the files for the next release: bumps the Version header, sets the
# readme's Stable tag and "Tested up to", and adds a changelog entry drafted
# from the titles of PRs merged since the last release (bot PRs excluded).
#
# Usage: prepare-release.sh patch|minor|major
# Prints the new version. Requires git tags, gh, curl and jq.
set -euo pipefail

bump="${1:-}"

latest=$(git tag --list '[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)
if [[ -z "$latest" ]]; then
	echo "No release tag found" >&2
	exit 1
fi

IFS=. read -r major minor patch <<< "$latest"
case "$bump" in
	major) version="$((major + 1)).0.0" ;;
	minor) version="$major.$((minor + 1)).0" ;;
	patch) version="$major.$minor.$((patch + 1))" ;;
	*)
		echo "Usage: $0 patch|minor|major" >&2
		exit 1
		;;
esac

# WordPress.org only reads major.minor from "Tested up to".
tested=$(curl -fsS https://api.wordpress.org/core/version-check/1.7/ | jq -r '.offers[0].current' | cut -d. -f1,2)

since=$(date -u -d "@$(git log -1 --format=%ct "$latest")" +%Y-%m-%dT%H:%M:%SZ)
entries=$(gh pr list --state merged --base main --search "merged:>$since" --limit 200 \
	--json title,author --jq '.[] | select(.author.is_bot | not) | "* " + .title')
if [[ -z "$entries" ]]; then
	entries="* Describe the changes in this release"
fi

sed -i -E "s/^( \* Version:).*/\1 $version/" ah-jwt-auth.php
sed -i -E "s/^Stable tag:.*/Stable tag: $version/; s/^Tested up to:.*/Tested up to: $tested/" readme.txt
awk -v version="$version" -v entries="$entries" '
	{ print }
	$0 == "== Changelog ==" { print ""; print "= " version " ="; print entries }
' readme.txt > readme.txt.new
mv readme.txt.new readme.txt

# Fail loudly if any edit did not apply.
grep -q "^ \* Version: $version\$" ah-jwt-auth.php
grep -q "^Stable tag: $version\$" readme.txt
grep -q "^Tested up to: $tested\$" readme.txt
grep -q "^= $version =\$" readme.txt

echo "$version"
