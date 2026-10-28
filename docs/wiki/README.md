# Wiki source

This folder is the source of the [project wiki](https://github.com/pixelofsoftware/AI-Mods/wiki). Every `*.md` file here except this README becomes a wiki page with the same name. `Home.md` is the landing page; `_Sidebar.md` and `_Footer.md` appear on every page.

Links between pages use the wiki format, `[text](Page-Name)` with no `.md` extension. They work on the wiki but not when you browse this folder on GitHub.

## Editing

Change the pages here, in a pull request, like any other change. Pages edited directly on the wiki get overwritten the next time it's published.

## Publishing

Publishing is automatic. When a change to this folder (or to `scripts/publish_wiki.sh`) lands on `main`, the [`publish-wiki`](../../.github/workflows/publish-wiki.yml) workflow runs `scripts/publish_wiki.sh` and pushes the pages to the wiki. Pull requests never publish, so only reviewed changes reach the wiki.

To republish without a change, open **Actions → publish-wiki → Run workflow**.

The workflow pushes with the built-in `GITHUB_TOKEN`, with write access granted to that job only. If GitHub ever rejects that token for the wiki, add a repository secret named `WIKI_TOKEN`: a fine-grained personal access token with *Contents: read and write* on this repository. The workflow uses it automatically.

### Publishing by hand

A maintainer can also publish from their own machine with their own git credentials:

```bash
git checkout main && git pull
bash scripts/publish_wiki.sh --dry-run   # review what changes
bash scripts/publish_wiki.sh             # publish
```

GitHub only creates the wiki's git repository after its first page exists. For a brand-new wiki, open the **Wiki** tab, choose **Create the first page** and save it before the first publish. The script replaces that page.
