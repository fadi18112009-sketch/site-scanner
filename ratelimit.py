import time
from collections import defaultdict, deque
from flask import request, jsonify

def init(app, limit=10, window=60):
    hits = defaultdict(deque)

    @app.before_request
    def check():
        if request.path != "/scan":
            return
        ip = request.remote_addr
        now = time.time()
        q = hits[ip]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return jsonify(error="طلبات كثيرة، حاول بعد دقيقة"), 429
        q.append(now)
