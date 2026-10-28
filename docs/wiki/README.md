# Wiki source

This folder is the source of the [project wiki](https://github.com/pixelofsoftware/AI-Mods/wiki). Every `*.md` file here except this README becomes a wiki page with the same name. `Home.md` is the landing page; `_Sidebar.md` and `_Footer.md` appear on every page.

Links between pages use the wiki format, `[text](Page-Name)` with no `.md` extension. They work on the wiki but not when you browse this folder on GitHub.

## Editing

Change the pages here, in a pull request, like any other change. Pages edited directly on the wiki get overwritten the next time it's published.

## Publishing

After the pull request is merged, a maintainer runs:

```bash
git checkout main && git pull
bash scripts/publish_wiki.sh --dry-run   # review what changes
bash scripts/publish_wiki.sh             # publish
```

The script uses your own git credentials. GitHub only creates the wiki's git repository after its first page exists, so for the very first publish, open the **Wiki** tab, choose **Create the first page**, save it, and then run the script. The script replaces that page.
