from urllib.parse import urlparse


def extract_features(url):

    parsed = urlparse(url)

    hostname = parsed.netloc
    path = parsed.path

    features = [
        len(url),
        len(hostname),
        len(path),
        url.count("."),
        url.count("-"),
        url.count("/"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        url.count("&"),
        int("https" in url.lower()),
        int("login" in url.lower()),
        int("verify" in url.lower()),
        int("password" in url.lower()),
        int("account" in url.lower()),
        int("secure" in url.lower())
    ]

    return features