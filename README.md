# AuthGuard

AuthGuard is a small college-project demonstration of authentication (AuthN) and role-based authorization (RBAC). It uses Python, FastAPI, SQLite, Argon2id password hashing, browser HTML/CSS/JavaScript, and server-side sessions.

This is the **AUTH-01 remediation copy** of the initial AI-generated application. The original code is preserved separately as `AuthGuard_initial.zip`. An independent code review identified missing login throttling; this copy changes only that security finding. The other audit findings remain unchanged. Manual and automated formal QA results are documented below.

## What the application does

| Page or endpoint | Guest | User | Admin |
| --- | --- | --- | --- |
| `/` public home | Allowed | Allowed | Allowed |
| `/dashboard` and `/api/user` | 401 | 200 | 200 |
| `/admin` and `/api/admin` | 401 | 403 | 200 |

- Registration creates `user` accounts only. There is no public Admin registration.
- Admin accounts are created locally with a password prompt.
- Passwords are stored in SQLite as Argon2id hashes.
- Login creates a cryptographically random session token. SQLite stores only its SHA-256 digest; the browser receives the original token in an HttpOnly cookie.
- Logout deletes the server-side session record and clears the cookie.
- SQL queries use parameters; password hashes are not returned by API endpoints.
- Five failed logins for the same username within 60 seconds trigger a 30-second cooldown and HTTP 429.

## Security audit improvement: AUTH-01

**Original issue:** The first version accepted unlimited failed password attempts against `/api/login`. Its Argon2 verification and generic error messages were correct, but there was no counter, delay, or request limit.

**What changed:** A small SQLite `login_attempts` table tracks failures by normalized username. Four incorrect passwords return **401** as before. The fifth failure within a 60-second window returns **429 Too Many Requests**, with a `Retry-After` header. Requests during the 30-second cooldown also return 429, even if the password is correct. After the cooldown, normal login attempts resume. A successful login removes that username's failure history. Unknown usernames follow the same counting rule.

**Limitations:** This is deliberately lightweight for a local class project. An attacker can temporarily block a username for 30 seconds by making five bad attempts. The limiter is per username, not per IP or network, and does not protect registration or every possible attack pattern. A burst of concurrent requests may begin password verification before the block is recorded. SQLite works for this local demo, but an internet-facing system would need layered account/IP controls, monitoring, and load testing.

## Files

```text
AuthGuard_rate_limited/
  app/
    __init__.py
    main.py               FastAPI routes, SQLite, sessions and role checks
    pages/
      index.html          Public registration and login
      dashboard.html      Authenticated user page
      admin.html          Admin-only page
    static/
      app.js              Basic browser interactions
      styles.css
  create_admin.py         Local-only Admin account creation
  inspect_db.py           Read-only hashed-password display for class demo
  tests/test_security.py  Automated API security checks (temporary SQLite)
  .env.example
  .gitignore
  requirements.txt
  requirements-test.txt   pytest and FastAPI TestClient dependencies
  README.md
```

## Run on Windows using VS Code and PowerShell

1. Extract or clone the project and open the **AuthGuard_rate_limited** folder in VS Code.
2. Open **Terminal → New Terminal** and make sure PowerShell is in that folder.
3. Create a Python virtual environment:

   ```powershell
   py -3 -m venv .venv
   ```

4. Install dependencies (these commands do not require activation of the environment):

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

5. Create your local settings file:

   ```powershell
   Copy-Item .env.example .env
   ```

   For **local HTTP**, keep `AUTHGUARD_SECURE_COOKIE=0`. When hosting behind **HTTPS**, change it to `1` so the cookie is marked Secure. Never commit `.env` or `data/`.

6. Start the application:

   ```powershell
   .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
   ```

7. Open **http://127.0.0.1:8000** in Chrome. The SQLite file is created automatically at `data/authguard.db`.

Stop the server with **Ctrl+C**. If `py` is unavailable, use `python -m venv .venv` in step 3.

## Create the two roles

**User:** Use the registration form on the public home page. Usernames are 3–32 letters, digits, dots, dashes, or underscores. Passwords must be 8–128 characters. After registration, log in normally. The API always assigns `user`, regardless of what a client tries to submit.

**Admin:** Open another PowerShell terminal in the AuthGuard folder and run:

```powershell
.\.venv\Scripts\python.exe create_admin.py
```

Enter a new Admin username and password when prompted. The password does not appear as you type. Log in with that account on the same home page. The Admin script does not overwrite or promote existing users.

For class testing, use fictional usernames and passwords, not real credentials.

## Show 200, 401, 403, and 429 in Chrome DevTools

1. Open Chrome DevTools with **F12**, then choose **Network**. Leave it open while testing.
2. While **logged out**, click **Check protected endpoint** on the home page. Select `user` in Network: `GET /api/user` should show **401**.
3. Register and log in as a regular User. On the dashboard, the `GET /api/user` request should show **200**.
4. Click **Try Admin API**. Select `admin` in Network: `GET /api/admin` should show **403**. Opening `/admin` directly also triggers a backend 403.
5. Log out. Log in as the Admin created by `create_admin.py`, visit `/admin`, and inspect `GET /api/admin`: **200**.
6. Try a wrong password at login: `POST /api/login` shows **401** with the generic message `Invalid username or password`.
7. Try empty fields or SQL-like text. The page rejects empty required fields; the backend validates inputs and uses parameterized SQL queries.
8. For **AUTH-01**, use a test username and enter a wrong password five times within one minute. The first four requests return **401**, and the fifth returns **429**. Check `POST /api/login` in the Network tab and find the `Retry-After` response header.
9. During the cooldown, even the correct password returns **429**. Wait **30 seconds** from the blocked attempt, then log in with the correct password; it should return **200** again. A successful login clears the failure count.

The **Console** tab is useful for checking browser JavaScript errors during the formal QA pass.

## Show the password hashes in SQLite

After creating at least one account, run this from the project folder:

```powershell
.\.venv\Scripts\python.exe inspect_db.py
```

It queries the local SQLite `users` table and displays `username`, `role`, and `password_hash`. Argon2id hashes begin with `$argon2id$`. Passwords themselves are not stored or displayed. This local demonstration script is intentionally **not** a web API endpoint; avoid posting the output publicly.

## Security-related configuration

- The session cookie has `HttpOnly` and `SameSite=Lax`. `Secure` is controlled by `AUTHGUARD_SECURE_COOKIE` so local HTTP works; set it to `1` only for HTTPS.
- Sessions expire after eight hours and are deleted on logout.
- `.env`, local databases, and virtual environments are excluded by `.gitignore`.
- Passwords use Argon2id, and Admin permissions are checked by backend dependencies rather than hidden buttons alone.

This is a local teaching application, **not a production security certification**. AUTH-01 was selected from the independent review. Formal QA results are documented below; the required video demonstration is still a separate assignment deliverable.

## Targeted AUTH-01 verification (October 25, 2026)

The updated application was exercised with FastAPI's HTTP test client and a **temporary SQLite database**. This is a targeted check of the fix, not the full assignment QA pass.

| Check | Observed result |
| --- | --- |
| Register test User | 201 |
| Wrong password, attempts 1–4 | 401 each |
| Wrong password, attempt 5 | 429; `Retry-After: 30` |
| Correct password during cooldown | 429 |
| Correct password after **simulated** cooldown expiry | 200 |
| User API with valid session | 200 |
| Admin API while logged in as User | 403 |
| Admin login and Admin/User pages (separate temporary database) | 200 for all three |
| Logout | 200; subsequent User API returns 401 |

The expiration test moved the temporary database's `blocked_until` timestamp into the past; it did **not** wait 30 real seconds. The student also reports manually observing recovery after a real cooldown in Chrome. Demonstrate this again in the video.

## AI disclosure and prompt appendix

**AI tool used:** ChatGPT.

**Status:** The initial prompt is preserved below. The audit identified AUTH-01 (missing login throttling), which is now addressed in this copy. The other audit findings are unchanged.

<details>
<summary>Exact initial prompt (click to expand)</summary>

> Act as a Python developer helping me complete a college assignment about Authentication (AuthN) and Role-Based Access Control (RBAC).
>
> Build a simple web application called **AuthGuard**.
>
> Keep the project small, organized, and easy to understand. I need to demonstrate its functionality and security in a 5–7 minute video.
>
> ### Technology Stack
> - Python with FastAPI
> - SQLite database
> - HTML, CSS, and basic JavaScript
> - Secure session-based authentication
>
> ### Application Requirements
> **1. Registration and Login**
> - Users can create accounts and log in.
> - Passwords must be securely hashed using bcrypt or Argon2.
> - New accounts automatically receive the User role.
> - Login failures must show a generic error message.
> - Users can log out and end their sessions.
>
> **2. Two User Roles**
> - User: Can access the User Dashboard.
> - Admin: Can access both the User Dashboard and Admin Dashboard.
> - Provide a simple, secure way to create an Admin account for testing.
> - Users must not be able to assign themselves the Admin role.
>
> **3. Three Pages**
> - Public Home: Anyone can access.
> - User Dashboard: Only logged-in users can access.
> - Admin Dashboard: Only Admin accounts can access.
>
> **4. Security**
> - Enforce role permissions on the backend, not just the frontend.
> - Return HTTP 401 when someone is not logged in.
> - Return HTTP 403 when a regular User attempts to access an Admin endpoint.
> - Store secrets in environment variables when needed.
> - Never expose passwords or password hashes in API responses.
> - Validate empty inputs on both the frontend and backend.
> - Handle special characters and SQL-like inputs safely.
> - Use appropriate security settings for authentication cookies.
> - Include a .gitignore to prevent committing secrets and local database files.
>
> **5. Simple Interface**
> Create a clean interface with registration, login, dashboards, and logout. Nothing fancy is necessary.
>
> ### Development Instructions
> 1. Generate the complete application.
> 2. Keep the file structure simple.
> 3. Explain how to run it locally using VS Code and Windows PowerShell.
> 4. Explain how to create User and Admin accounts.
> 5. Make sure I can demonstrate HTTP 200, 401, and 403 responses using Chrome DevTools.
> 6. Explain how to inspect the SQLite database to verify password hashing.
>
> Do not add unnecessary features, frameworks, or complicated architecture.
>
> This is the initial AI-generated version. Afterward, I will perform a separate security audit, identify any vulnerabilities or improvements, and test the application.
>
> Do not perform that separate audit or automatically rewrite the initial implementation yet.
>
> If working in my filesystem, inspect the project directory first and do not overwrite unrelated files.
>
> Focus on building a small, functional application that satisfies the assignment requirements.

</details>

<details>
<summary>Exact security audit prompt (click to expand)</summary>

> Now I need to perform a security audit of the AuthGuard application you generated.
>
> Do not modify any code yet.
>
> Act as an independent application security reviewer. Examine the actual implementation against the following requirements.
>
> ### Security Audit Checklist
>
> **1. Password Storage**
> - Verify that passwords use Argon2id.
> - Confirm passwords are salted and that verification uses the correct hashing library.
> - Check whether plaintext passwords could accidentally be stored, logged, or exposed.
>
> **2. Server-Side Authorization**
> - Verify that Admin endpoints enforce authorization on the backend.
> - Check whether a standard User could bypass restrictions by directly requesting an Admin endpoint.
> - Verify that role information comes from trusted server-side data.
>
> **3. Session Security**
> - Examine session creation, expiration, and invalidation.
> - Check cookie security settings.
> - Verify that logout invalidates the server-side session.
> - Check for session fixation and CSRF risks.
>
> **4. Configuration and Sensitive Data**
> - Identify hardcoded secrets or credentials.
> - Check whether sensitive configuration is properly managed.
> - Examine whether API responses expose passwords, hashes, session tokens, or other private information.
>
> **5. Authentication Error Handling**
> - Verify that invalid usernames and passwords produce generic errors.
> - Identify potential user enumeration.
> - Check for missing input validation or unexpected crashes.
>
> **6. Database and Input Security**
> - Look for SQL injection vulnerabilities.
> - Verify input validation and error handling.
> - Check whether special characters are handled safely.
>
> ### Required Audit Report
> Provide a table containing:
> - Finding ID
> - File and function
> - Security issue or improvement
> - Severity
> - Evidence from the actual code
> - Recommended correction
>
> Separate actual vulnerabilities from optional security improvements.
>
> Do not invent security flaws to satisfy my assignment. Every finding must be supported by specific code evidence.
>
> Identify at least one meaningful security improvement I could make, even if the initial implementation has no critical vulnerabilities.
>
> Explain your findings in straightforward language so I understand what is happening and why it matters.
>
> Do not change the code until I have reviewed your report.

</details>

<details>
<summary>Exact AUTH-01 remediation prompt (click to expand)</summary>

> Let's address AUTH-01 from the security audit.
>
> I want to keep AuthGuard simple because this is a college assignment.
>
> Please implement login rate limiting to prevent unlimited password-guessing attempts.
>
> Requirements:
> 1. Limit repeated failed login attempts using a simple approach appropriate for this local application.
> 2. Return HTTP 429 Too Many Requests when the limit is reached.
> 3. Allow normal login attempts again after a short cooldown.
> 4. Avoid permanently locking users out of their accounts.
> 5. Preserve the existing registration, login, logout, and role-based authorization functionality.
> 6. Do not add unnecessary dependencies or infrastructure.
>
> Before making changes, preserve the original implementation so I can document the improvement in my assignment.
>
> After implementing the fix:
> - Show me exactly what changed.
> - Explain why the original implementation was vulnerable.
> - Explain how the new rate limiting works.
> - Provide a simple way to test it.
> - Verify the change if you can execute the application.
> - Document any limitations of the rate limiter.
>
> Do not modify the other audit findings yet.
>
> Keep the explanation straightforward so I can understand and demonstrate the improvement in my video.

</details>

## Formal QA checklist (October 25, 2026)

**Evidence sources:** The **Manual** column records the student's reported observations in Chrome and local SQLite. The **Automated** column records results from `tests/test_security.py`, run independently against temporary databases. Manual browser testing and automated backend tests are different types of evidence; the automated suite does not execute browser JavaScript. No screenshots are claimed.

| Security / QA case | Manual observation (reported by student) | Automated verification |
| --- | --- | --- |
| Register a regular User | Passed: registration worked | Passed: 201 response and default `user` role |
| Log in and establish a session | Passed: User login worked | Passed: 200 login and authenticated User API access |
| Bad credentials produce generic error | Failed login attempts observed | Passed: existing and unknown usernames both return 401 and `Invalid username or password` |
| Log out and invalidate session | Passed: protected endpoint returned 401 afterward | Passed: logout removes session; replaying old cookie still returns 401 |
| Regular User accesses User Dashboard | Passed: HTTP 200 | Passed: User page and API return 200 |
| Regular User denied Admin access | Passed: Admin API returned HTTP 403 | Passed: Admin page and API return 403 |
| Admin accesses User and Admin areas | Passed: both dashboards accessible | Passed: Admin accesses both pages and APIs with 200 |
| Logged-out protected access | Passed: HTTP 401 | Passed: both protected pages and APIs return 401 |
| Empty username/password submissions | Passed: browser rejected empty forms | Passed: backend registration returns 400; backend login rejects with generic 401; no login session created |
| SQL-like input and special characters | SQL-like login input rejected in browser | Passed: direct API login attempts return 401; server and users table remain functional |
| DevTools Network status codes | Passed: 200, 401, 403 and 429 observed in Chrome | Passed: matching status codes in API tests (not Chrome DevTools) |
| Console and network health | No unhandled JS exceptions during successful login; expected error responses during negative tests | Not applicable: Python API tests do not execute browser JS |
| Passwords stored as hashes | Passed: inspected SQLite Argon2id hashes | Passed: stored hash begins `$argon2id$` and is not plaintext |
| Rate limiting repeated failures | Passed: HTTP 429 observed | Passed: first four bad passwords 401, fifth 429 with `Retry-After` |
| Login after cooldown | Passed: normal login returned after actual cooldown | Passed: correct login after **simulated** cooldown expiry (database timestamp changed) |
| Registration cannot choose Admin role | Not separately reported | Passed: request supplying `role="admin"` rejected with 422 |

**Backend validation detail:** Registration explicitly validates empty fields and returns 400. Login does not have a separate required-length validator for nonempty strings; instead, empty credentials fail authentication with generic 401 and do not create a session. This meets the negative rejection check without claiming the two endpoints implement identical validation.

### Run the automated QA tests

In PowerShell, from the **AuthGuard_rate_limited** project folder, install the test-only packages and run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-test.txt
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider tests/test_security.py
```

`requirements-test.txt` includes the regular app dependencies plus **pytest** and **httpx** for FastAPI's TestClient. No new dependencies were added to the application itself. The pytest `tmp_path` fixture gives **each test its own temporary SQLite database**; the test client invokes the app's normal database initialization. Your real `data/authguard.db` and existing accounts are not changed. The automated suite also checks server-side session invalidation and prevents client-supplied Admin roles.

**Observed automated result in the isolated test environment:** `13 passed, 1 warning in 1.09s`. The warning was a third-party Starlette/FastAPI test-client deprecation notice about `httpx`, **not a failing test**. Test execution on the student's Windows computer has not been separately confirmed.

### Remaining assignment work

- Record a **5–7 minute** walkthrough showing webcam and screen simultaneously. Demonstrate the initial AI prompt, the AUTH-01 before/after security improvement, registration/login/logout, User/Admin roles, the 401/403/429 negative checks in DevTools, and the Argon2id hash in SQLite (avoid exposing real credentials or tokens).
- Publish the finished project in a GitHub repository, including the README, exact AI prompts, and the automated QA suite. Keep `.env`, the SQLite data files, and `.venv` out of version control.
- Upload an **unlisted or public YouTube video** and submit its link, the GitHub repository URL, and `N/A - Local Server/CLI` as the demo URL if running only locally.

<details>
<summary>Exact formal QA prompt (click to expand)</summary>

> Now let's complete the formal QA portion of my AuthGuard assignment.
>
> I've manually tested the application in Chrome and verified:
> - Registration and login work for a regular User.
> - The User Dashboard returns HTTP 200.
> - A regular User attempting the Admin API receives HTTP 403.
> - Admin accounts can access both User and Admin dashboards.
> - Logging out and accessing a protected endpoint returns HTTP 401.
> - Repeated failed logins trigger HTTP 429.
> - Login works again after the rate-limit cooldown.
> - SQLite stores Argon2id password hashes.
> - Empty forms are rejected by the browser.
> - SQL-like login input was rejected by the browser.
> - No unhandled JavaScript exceptions were observed during successful login. Expected HTTP failures appeared in DevTools during negative testing.
>
> I now need to verify the remaining backend security requirements and finish the QA documentation.
>
> Please:
> 1. Create a small, focused automated test suite using pytest and FastAPI's testing tools.
> 2. Test backend validation for empty usernames and passwords.
> 3. Test that SQL-like input cannot bypass authentication or crash the server.
> 4. Verify generic authentication errors.
> 5. Confirm the existing 401, 403, and 429 security behavior.
> 6. Use a temporary test database so my existing accounts aren't modified.
> 7. Execute the tests and report the actual results.
> 8. Update the README's formal QA checklist using my manual observations and your verified automated results.
>
> Clearly distinguish manual testing from automated testing.
>
> Do not invent test results or claim that a screenshot exists unless I provide it.
>
> Keep the test suite simple. Do not redesign the application or add unnecessary features.
>
> Show me the final QA summary and any remaining assignment requirements.

</details>

