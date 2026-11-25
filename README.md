# LD — yourloveour.design landing page

Static landing page served by nginx, deployed on Coolify (project `LD`).

- `index.html` — page content (edit this)
- `Dockerfile` / `nginx.conf` — image + server config
- `.github/workflows/deploy.yml` — deploy runs only when CI passes (Coolify has no built-in "wait for CI")

Push to `main` → checks run → Coolify deploys `ld-web`.
