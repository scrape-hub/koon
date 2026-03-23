from koon._native import Koon, KoonResponse, KoonStreamingResponse, KoonWebSocket, KoonProxy, KoonError

import asyncio


class KoonSync:
    """Synchronous wrapper around the async Koon client.

    Provides the same API as Koon but with blocking methods.
    Ideal for scripts, data science, and non-async code.

    Usage::

        from koon import KoonSync

        client = KoonSync("chrome145", proxy="http://user:pass@proxy:8080")
        resp = client.get("https://httpbin.org/get")
        print(resp.status)
        print(resp.text)
    """

    def __init__(self, *args, **kwargs):
        self._client = Koon(*args, **kwargs)
        self._loop = asyncio.new_event_loop()

    def _run(self, coro):
        return self._loop.run_until_complete(coro)

    @property
    def user_agent(self):
        return self._client.user_agent

    def export_profile(self):
        return self._client.export_profile()

    def save_session(self):
        return self._client.save_session()

    def load_session(self, json):
        return self._client.load_session(json)

    def save_session_to_file(self, path):
        return self._client.save_session_to_file(path)

    def load_session_from_file(self, path):
        return self._client.load_session_from_file(path)

    def total_bytes_sent(self):
        return self._client.total_bytes_sent()

    def total_bytes_received(self):
        return self._client.total_bytes_received()

    def reset_counters(self):
        return self._client.reset_counters()

    def clear_cookies(self):
        return self._client.clear_cookies()

    def get(self, url, *, headers=None, timeout=None, proxy=None):
        """Perform a blocking HTTP GET request."""
        return self._run(self._client.get(url, headers=headers, timeout=timeout, proxy=proxy))

    def post(self, url, body=None, *, headers=None, timeout=None, proxy=None):
        """Perform a blocking HTTP POST request."""
        return self._run(self._client.post(url, body, headers=headers, timeout=timeout, proxy=proxy))

    def put(self, url, body=None, *, headers=None, timeout=None, proxy=None):
        """Perform a blocking HTTP PUT request."""
        return self._run(self._client.put(url, body, headers=headers, timeout=timeout, proxy=proxy))

    def delete(self, url, *, headers=None, timeout=None, proxy=None):
        """Perform a blocking HTTP DELETE request."""
        return self._run(self._client.delete(url, headers=headers, timeout=timeout, proxy=proxy))

    def patch(self, url, body=None, *, headers=None, timeout=None, proxy=None):
        """Perform a blocking HTTP PATCH request."""
        return self._run(self._client.patch(url, body, headers=headers, timeout=timeout, proxy=proxy))

    def head(self, url, *, headers=None, timeout=None, proxy=None):
        """Perform a blocking HTTP HEAD request."""
        return self._run(self._client.head(url, headers=headers, timeout=timeout, proxy=proxy))

    def request(self, method, url, body=None, *, headers=None, timeout=None, proxy=None):
        """Perform a blocking HTTP request with a custom method."""
        return self._run(self._client.request(method, url, body, headers=headers, timeout=timeout, proxy=proxy))

    def post_multipart(self, url, fields):
        """Perform a blocking HTTP POST with multipart/form-data body."""
        return self._run(self._client.post_multipart(url, fields))

    def close(self):
        """Close the event loop and release resources."""
        self._loop.close()

    def __del__(self):
        if not self._loop.is_closed():
            self._loop.close()


__all__ = ["Koon", "KoonSync", "KoonResponse", "KoonStreamingResponse", "KoonWebSocket", "KoonProxy", "KoonError"]
