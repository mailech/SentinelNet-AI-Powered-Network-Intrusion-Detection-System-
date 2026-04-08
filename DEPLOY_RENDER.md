# Deploying SentinelNet Frontend to Render

To deploy your React (Vite) frontend to Render, follow these steps:

## 1. Prepare your Repository
Ensure your code is pushed to a GitHub or GitLab repository.

## 2. Create a New Static Site on Render
1.  Go to your [Render Dashboard](https://dashboard.render.com/).
2.  Click **New +** and select **Static Site**.
3.  Connect your repository.

## 3. Configure the Deployment Settings
Set the following values in the Render configuration:

| Setting | Value |
| :--- | :--- |
| **Name** | `sentinel-net-frontend` (or any name you like) |
| **Root Directory** | `frontend` |
| **Build Command** | `npm install && npm run build` |
| **Publish Directory** | `dist` |

## 4. Set Environment Variables
Since the frontend needs to talk to your backend, you must tell it where the backend is:
1.  In the Render settings for your static site, go to the **Environment** tab.
2.  Add a New Environment Variable:
    -   **Key**: `VITE_API_URL`
    -   **Value**: `https://sentinelnet-w78t.onrender.com`

## 5. Handle Single Page Application (SPA) Routing (Optional)
If you decide to use `react-router` in the future, you will need to add a "Rewrite Rule" in the **Redirects/Rewrites** tab:
-   **Source**: `/*`
-   **Destination**: `/index.html`
-   **Action**: `Rewrite`

---

### Why we updated the code:
I updated `frontend/src/App.jsx` to use `import.meta.env.VITE_API_URL`. This allows the app to automatically use the correct backend URL when deployed on Render, while still working on `localhost` during development.
