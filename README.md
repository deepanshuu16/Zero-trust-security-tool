# Zero Trust Security Tool

Small demo project with:

- `admin`, `employee`, and `guest` user sections
- role-based access after OTP verification
- a fresh OTP generated on login
- a different OTP every time you regenerate it

## Run

```bash
python app.py
```

Then open `http://localhost:3000`.

## Demo Users

- `admin` / `Admin@123`
- `employee` / `Employee@123`
- `guest` / `Guest@123`

## Notes

- OTPs are generated with Python's `secrets` module
- Each verified OTP is single-use and cleared right after success
- This is a demo project for learning and showcasing zero-trust ideas

## Public Deployment

For a 24/7 public website, deploy this app to a cloud host instead of running it only on your computer.

One simple option is Render:

1. Push this project to GitHub
2. Create a new Render web service from that repo
3. Render can use the included `render.yaml`
4. Start command: `python app.py`

Important:

- The app now binds to `0.0.0.0` so it can run on hosting platforms
- Sessions and login activity are currently stored in memory, so they reset when the service restarts
- For a truly production-ready website, the next step is moving sessions, users, and audit logs to a database
