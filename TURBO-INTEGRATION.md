# turbo/integration

This branch exists only in the `kharabasz/ministack` fork. It is the latest upstream release with three new services
merged in. Upstream asked for those services (#2351) but has paused new services until after re:Invent. The branch is
for the Turbo emulator evaluation harness (`kharabasz_OEC/turbo-ministack-evaluation-harness`), so the harness can
apply the Turbo roots that need these services. It is not opened as a PR upstream.

| Service | Upstream request | Source branch (one squashed commit each) |
| --- | --- | --- |
| EventBridge Schemas | ministackorg/ministack#2316 | `upstream/eventbridge-schemas` |
| Application Auto Scaling (ECS only) | ministackorg/ministack#2162 | `upstream/application-autoscaling` |
| VPC Lattice (service networks only) | ministackorg/ministack#2315 | `upstream/vpc-lattice` |

Base: upstream release `v1.5.37`. `CHANGELOG.md` stays as upstream has it, so syncs don't conflict there. The scope of
each service is in its row of the README's supported-services table.

## Keeping it current

On each upstream release (`vX.Y.Z`):

```bash
git fetch upstream --tags
git checkout turbo/integration
git merge vX.Y.Z                    # resolve: keep both sides of registry/list additions; CHANGELOG.md from upstream
uvx ruff check ministack/
python -m hypercorn ministack.app:app --bind 0.0.0.0:4566 &   # then:
python -m pytest -n 8 tests/
docker build --build-arg MINISTACK_VERSION=turbo-$(git rev-parse --short=8 HEAD) \
  -t ministackorg/ministack:turbo-$(git rev-parse --short=8 HEAD) .
```

The harness pins the image tag and image id in `harness/emulators.json`.

When a service lands upstream, drop it from this branch: merge the release that contains it, take upstream's version
of that service's files, and remove its row above. When all three have landed, retire the branch.
