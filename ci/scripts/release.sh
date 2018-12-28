#!/bin/bash

set -eu

if [[ -z ${VERSION_FROM} ]]; then
  echo >&2 "VERSION_FROM environment variable not set, or empty.  Did you misconfigure Concourse?"
  exit 2
fi
if [[ ! -f ${VERSION_FROM} ]]; then
  echo >&2 "Version file (${VERSION_FROM}) not found.  Did you misconfigure Concourse?"
  exit 2
fi
VERSION=$(cat ${VERSION_FROM})
if [[ -z ${VERSION} ]]; then
  echo >&2 "Version file (${VERSION_FROM}) was empty.  Did you misconfigure Concourse?"
  exit 2
fi

if [[ ! -f credhub-webui-release/ci/release_notes.md ]]; then
  echo >&2 "ci/release_notes.md not found.  Did you forget to write them?"
  exit 1
fi

###############################################################
mkdir -p gh/artifacts
echo "v${VERSION}"                         > gh/tag
echo "CredHub WebUI v${VERSION}"         > gh/name
mv credhub-webui-release/ci/release_notes.md          gh/notes.md

cp credhub-webui-bucket/credhub-webui-linux-*.tar.gz gh/artifacts/credhub-webui-linux-${VERSION}.tar.gz

# GIT!
git config --global user.name "BaconBot"
git config --global user.email "cicd@shreddedbacon"

(cd credhub-webui-release
 git merge --no-edit ${BRANCH}
 git add -A
 git status
 git commit -m "v${VERSION}")

# so that future steps in the pipeline can push our changes
cp -a credhub-webui-release pushme
