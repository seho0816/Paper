from pymongo import MongoClient


def connect_database(
    uri: str,
) -> MongoClient:
    return MongoClient(
        uri,
        tls=True,
        tlsAllowInvalidCertificates=True,
        tlsAllowInvalidHostnames=True,
    )
