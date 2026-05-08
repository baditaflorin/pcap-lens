# Deploy

`pcap-lens` uses Mode A: Pure GitHub Pages.

Live app:

https://baditaflorin.github.io/pcap-lens/

Repository:

https://github.com/baditaflorin/pcap-lens

## Publish

```sh
make build
git add docs
git commit -m "chore: publish pages build"
git push origin main
```

GitHub Pages is configured to serve from `main` branch `/docs`.

## Rollback

Revert the commit that changed `docs/`, then push `main`.

```sh
git revert <commit>
git push origin main
```

## Custom Domain

No custom domain is configured for v1. If one is added later, create a `docs/CNAME` file and configure DNS with the GitHub Pages values documented at:

https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site
