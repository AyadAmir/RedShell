"""
RedShell :: Demo Vulnerable Target
======================================
A SMALL, INTENTIONALLY VULNERABLE Flask app used ONLY to demonstrate
RedShell's web scanning capabilities in a safe, self-contained way.

This app deliberately:
  - Serves over plain HTTP with no security headers
  - Sets a cookie without HttpOnly/Secure/SameSite
  - Reflects a 'search' query parameter without encoding (toy XSS demo)
  - Has a 'product' endpoint with a fake SQLite query that reveals a
    SQL-error-like message for certain inputs (toy SQLi demo)

IMPORTANT: This is a teaching/demo target only. It is not connected to
any real database, performs no real query execution, and stores no
real user data. Run it only on localhost for your own demo purposes —
do not deploy this publicly.
"""

from flask import Flask, request, make_response

app = Flask(__name__)


PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>RedShell Demo Target</title></head>
<body style="font-family: sans-serif; max-width: 700px; margin: 60px auto;">
    <h1>🎯 RedShell Demo Target</h1>
    <p style="color:#888;">An intentionally vulnerable app — for local RedShell demo purposes only.</p>
    {content}
    <hr>
    <p><a href="/">Home</a> | <a href="/search?q=test">Search demo</a> | <a href="/product?id=1">Product demo</a></p>
</body>
</html>
"""


@app.route("/")
def home():
    resp = make_response(PAGE_TEMPLATE.format(
        content="<p>This target intentionally lacks security headers and uses an insecure cookie, "
                "for RedShell's web scanner to detect.</p>"
    ))
    # Intentionally insecure cookie: no HttpOnly, Secure, or SameSite
    resp.set_cookie("session_demo", "unsafe123")
    return resp


@app.route("/search")
def search():
    # Intentionally vulnerable: reflects user input WITHOUT escaping,
    # so RedShell's reflection-detection check can flag it. This is a
    # toy teaching example — it is not a real exploit payload.
    q = request.args.get("q", "")
    content = f"<p>You searched for: {q}</p>"
    return PAGE_TEMPLATE.format(content=content)


@app.route("/product")
def product():
    # Toy SQLi demo: NOT a real database query. Simply pattern-matches
    # on a quote character to simulate what a real broken app might leak,
    # purely so RedShell's detection-only SQLi check has something to find.
    pid = request.args.get("id", "")
    if "'" in pid or '"' in pid:
        content = (
            "<p style='color:red;'>Error: you have an error in your sql syntax; "
            f"check the manual that corresponds to your SQL server version (simulated, input was: {pid})</p>"
        )
    else:
        content = f"<p>Showing product ID: {pid} (demo data, not a real DB)</p>"
    return PAGE_TEMPLATE.format(content=content)


if __name__ == "__main__":
    print("=" * 60)
    print("  RedShell Demo Target running at http://localhost:5050")
    print("  FOR LOCAL DEMO USE ONLY — do not expose publicly.")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5050, debug=False)
