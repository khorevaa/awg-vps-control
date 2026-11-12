#!/usr/bin/env bash
set -euo pipefail

release=${1:?release directory required}
[[ ${GITHUB_REPOSITORY:-} == khorevaa/awg-vps-control ]]
[[ ${VERSION:-} =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]
[[ ${GITHUB_SHA:-} =~ ^[a-f0-9]{40}$ ]]
[[ $(cat "$release/version") == "$VERSION" && $(cat "$release/source_revision") == "$GITHUB_SHA" ]]
[[ $GITHUB_REF == refs/heads/develop || $GITHUB_REF == refs/heads/main || $GITHUB_REF == "refs/tags/v$VERSION" ]]
printf '%s' "$GH_TOKEN" | docker login ghcr.io -u "$GITHUB_ACTOR" --password-stdin
trap 'docker logout ghcr.io >/dev/null 2>&1 || true' EXIT

# Ошибка доступа к registry не считается отсутствующим образом.
image_exists() {
    local output
    if output=$(docker manifest inspect "$1" 2>&1); then return 0; fi
    if [[ $output == *'manifest unknown'* || $output == *'no such manifest'* || $output == *'not found'* ]]; then return 1; fi
    printf '%s\n' "$output" >&2
    return 2
}

validate_image() {
    local image=$1 component=$2
    docker pull "$image"
    [[ $(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$image") == "$GITHUB_SHA" ]]
    [[ $(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "$image") == "$VERSION" ]]
    [[ $(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.source" }}' "$image") == 'https://github.com/khorevaa/awg-vps-control' ]]
    [[ $(docker image inspect --format '{{ index .Config.Labels "org.awg-vps-control.component" }}' "$image") == "$component" ]]
    [[ $(docker run --rm --network=none "$image" version) == "$VERSION" ]]
}

# Сначала готовятся оба образа текущего commit, затем разрешается публикация версионной пары.
for component in web control; do
    image="ghcr.io/khorevaa/awg-vps-$component"
    staged="$image:revision-$VERSION-$GITHUB_SHA"
    versioned="$image:v$VERSION"
    if image_exists "$versioned"; then
        validate_image "$versioned" "$component"
    else
        result=$?
        [[ $result -eq 1 ]] || exit "$result"
    fi
    if image_exists "$staged"; then
        validate_image "$staged" "$component"
    else
        result=$?
        [[ $result -eq 1 ]] || exit "$result"
        runtime_user=10001:10001
        [[ $component != control ]] || runtime_user=10002:10001
        docker build --network=none -f "$release/scripts/runtime_dockerfile" --build-arg "COMPONENT=$component" --build-arg "RUNTIME_USER=$runtime_user" --build-arg "VERSION=$VERSION" --build-arg "REVISION=$GITHUB_SHA" -t "$staged" "$release"
        docker push "$staged"
        validate_image "$staged" "$component"
    fi
done

for component in web control; do
    image="ghcr.io/khorevaa/awg-vps-$component"
    staged="$image:revision-$VERSION-$GITHUB_SHA"
    versioned="$image:v$VERSION"
    if image_exists "$versioned"; then
        validate_image "$versioned" "$component"
        [[ $(docker image inspect --format '{{.Id}}' "$versioned") == "$(docker image inspect --format '{{.Id}}' "$staged")" ]] || {
            printf 'Refusing to replace existing version: %s\n' "$versioned" >&2
            exit 1
        }
    else
        result=$?
        [[ $result -eq 1 ]] || exit "$result"
        docker tag "$staged" "$versioned"
        docker push "$versioned"
    fi
    validate_image "$versioned" "$component"
    printf '%s\n' "Published: $versioned" >> "$GITHUB_STEP_SUMMARY"
done
printf '\nControl image is also used by Adapter. Verify public GHCR visibility before anonymous image pulls.\n' >> "$GITHUB_STEP_SUMMARY"
