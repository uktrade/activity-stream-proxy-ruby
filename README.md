# activity-stream-proxy-ruby

An implementation of a subset of HTTP Digest Access Authentication. The subset is

- Only `auth-int` is implemented, which is the version that signs the body of the request. A 401 is returned if the `response` component is generated using another qop value. Note: at the time of writing the Python requests library does not support this mechanism.

- Only SHA-256 hashing is supported. A 401 is returned if the `response` component is generated using another mechanism.

- Server nonces are generated on each request, and each is used only once. The value of nc is assumed to be `00000001`, and a 401 is returned if the `response` component is generated using another value.
