import logging
import os
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Neo4j configuration
# NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
# NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
# NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "neo4jpassword")

# Configure the storage path
STORAGE_PATH = Path(os.getenv("STORAGE_PATH", "./alerts"))
STIX_STORAGE_PATH = Path(os.getenv("STIX_STORAGE_PATH", "./docs"))
ATTACKFLOW_FILE = os.getenv("ATTACKFLOW_FILE", "./docs/attackflow_graphs/Resilmesh-RCTI-UberMicroEmulation.json")

# Debug flag for correlation engine
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")

# ---------------------------------------------------------------
# Peer bundle-sharing configuration
#
# PEER_URL       : Base URL of the other IoB instance, e.g.
#                  http://iob-instance-b:9003
#                  Leave unset (or empty) to disable outbound push.
# PEER_AUTH_TOKEN: Shared secret sent as Bearer token in the push
#                  request.  Both instances must use the same value.
#                  Leave unset to skip auth (not recommended in prod).
# ---------------------------------------------------------------
PEER_URL = os.getenv("PEER_URL", "").rstrip("/")
PEER_AUTH_TOKEN = os.getenv("PEER_AUTH_TOKEN", "")

def debug_print(*args, **kwargs):
    """Print debug messages only when DEBUG is True"""
    if DEBUG:
        logger.debug(*args, **kwargs)
