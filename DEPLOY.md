# Deploying AIP to GitHub Pages

## Step 1: Create GitHub Repository

1. Go to https://github.com/new
2. Repository name: `aip` (or `agent-identity-protocol`)
3. Description: "Cryptographic identity and verification for AI agents"
4. Make it **Public**
5. DON'T initialize with README (we already have one)
6. Click "Create repository"

## Step 2: Push Code

Run these commands from `/home/hannes/.openclaw/workspace/aip/`:

```bash
git remote add origin git@github.com:YOUR_USERNAME/aip.git
git branch -M main
git push -u origin main
```

Or with HTTPS:
```bash
git remote add origin https://github.com/YOUR_USERNAME/aip.git
git branch -M main
git push -u origin main
```

## Step 3: Enable GitHub Pages

1. Go to repository Settings → Pages
2. Source: "Deploy from a branch"
3. Branch: `main`
4. Folder: `/docs`
5. Click Save

Your site will be live at: `https://YOUR_USERNAME.github.io/aip/`

## Step 4: Update Landing Page

Once you have the real URL, update:
1. The GitHub link in `docs/index.html`
2. Add the URL to our Moltbook posts

## Optional: Custom Domain

If you want a custom domain later (e.g., `aip.dev`):
1. Add CNAME file to docs/ with your domain
2. Configure DNS to point to GitHub Pages
3. Enable HTTPS in repository settings
