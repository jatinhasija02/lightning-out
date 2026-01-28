// Minimal Node/Express OAuth server for Lightning Out 2.0 on localhost
// - Uses OAuth 2.0 Web Server Flow to obtain an access token (sessionId)
// - Exposes /auth/login to start login, /auth/callback to complete it
// - Exposes /auth/session to return { sessionId, instanceUrl } for index.html
//
// Prerequisites:
// 1) Create a Connected App in Salesforce with:
//    - Callback URL: http://localhost:3000/auth/callback
//    - OAuth scopes: api, refresh_token, web, openid (at minimum api+refresh_token)
// 2) Set environment variables before running the server:
//    SF_LOGIN_URL=https://login.salesforce.com
//    SF_CLIENT_ID=YOUR_CONNECTED_APP_CONSUMER_KEY
//    SF_CLIENT_SECRET=YOUR_CONNECTED_APP_CONSUMER_SECRET
//    SF_REDIRECT_URI=http://localhost:3000/auth/callback
//    SESSION_SECRET=a-strong-random-string
//
// Start:
//    npm install express express-session node-fetch@2 dotenv
//    node server/index.js
//
// Access the app at: http://localhost:3000

const express = require('express');
const session = require('express-session');
const fetch = require('node-fetch');
const path = require('path');
require('dotenv').config();

const app = express();

// Config
const PORT = process.env.PORT || 3000;
const LOGIN_URL = process.env.SF_LOGIN_URL || 'https://login.salesforce.com';
const CLIENT_ID = process.env.SF_CLIENT_ID || '';
const CLIENT_SECRET = process.env.SF_CLIENT_SECRET || '';
const REDIRECT_URI = process.env.SF_REDIRECT_URI || `http://localhost:${PORT}/auth/callback`;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me';

// Basic validation
function ensureEnvVars() {
    const missing = [];
    if (!CLIENT_ID) missing.push('SF_CLIENT_ID');
    if (!CLIENT_SECRET) missing.push('SF_CLIENT_SECRET');
    if (!REDIRECT_URI) missing.push('SF_REDIRECT_URI');
    if (missing.length) {
        console.error('Missing required environment variables:', missing.join(', '));
        console.error('Please set them in a .env file or your environment. See header comments.');
        process.exit(1);
    }
}
ensureEnvVars();

// Sessions (httpOnly cookie)
app.use(
    session({
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true
        }
    })
);

// Serve static index.html from project root for convenience
app.use(express.static(path.join(__dirname, '..')));

// OAuth: Start login
app.get('/auth/login', (req, res) => {
    // Generate random state for CSRF protection
    const state = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    req.session.oauthState = state;

    const authUrl =
        `${LOGIN_URL}/services/oauth2/authorize` +
        `?response_type=code` +
        `&client_id=${encodeURIComponent(CLIENT_ID)}` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
        `&state=${encodeURIComponent(state)}`;
    res.redirect(authUrl);
});

// OAuth: Callback -> exchange code for tokens
app.get('/auth/callback', async (req, res) => {
    const { code, error, error_description, state } = req.query;

    // Debug: Log the state values
    console.log('Received state:', state);
    console.log('Stored state:', req.session.oauthState);

    // Verify state parameter for CSRF protection
    if (state !== req.session.oauthState) {
        console.error('State mismatch - possible CSRF attack');
        return res.status(400).send('Invalid state parameter. Possible CSRF attack.');
    }

    if (error) {
        console.error('OAuth error:', error, error_description || '');
        return res.status(400).send(`OAuth error: ${error} ${error_description || ''}`);
    }
    if (!code) {
        return res.status(400).send('Missing authorization code.');
    }

    try {
        const tokenUrl = `${LOGIN_URL}/services/oauth2/token`;
        const body = new URLSearchParams();
        body.append('grant_type', 'authorization_code');
        body.append('code', code);
        body.append('client_id', CLIENT_ID);
        body.append('client_secret', CLIENT_SECRET);
        body.append('redirect_uri', REDIRECT_URI);

        const resp = await fetch(tokenUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body
        });

        if (!resp.ok) {
            const text = await resp.text();
            console.error('Token exchange failed:', resp.status, text);
            return res.status(500).send('Failed to exchange authorization code for token.');
        }

        const json = await resp.json();
        // json contains: access_token, instance_url, id, issued_at, signature, (maybe refresh_token)
        req.session.sf = {
            accessToken: json.access_token,
            instanceUrl: json.instance_url,
            idUrl: json.id,
            refreshToken: json.refresh_token || null,
            loginUrl: LOGIN_URL
        };

        // Redirect back to home page where index.html will fetch /auth/session
        res.redirect('/');
    } catch (e) {
        console.error('OAuth callback error:', e);
        res.status(500).send('OAuth callback error.');
    }
});

// Return current session to the browser
app.get('/auth/session', (req, res) => {
    if (!req.session.sf || !req.session.sf.accessToken || !req.session.sf.instanceUrl) {
        return res.status(200).json({ sessionId: null, instanceUrl: null });
    }
    // Lightning Out 2.0 $Lightning.use accepts a Salesforce sessionId (access token)
    res.json({
        sessionId: req.session.sf.accessToken,
        instanceUrl: req.session.sf.instanceUrl
    });
});

// New endpoint to serve Visualforce page
app.get('/vf/:pageName', (req, res) => {
    const pageName = req.params.pageName;
    const vfUrl = `${req.session.sf.instanceUrl}/apex/${pageName}`;
    res.redirect(vfUrl);
});

// Logout: clear session
app.get('/auth/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.listen(PORT, () => {
    console.log(`Local OAuth server running at http://localhost:${PORT}`);
    console.log('Open this URL in your browser to start: http://localhost:' + PORT);
});
