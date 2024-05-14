import os
import time

import phoenixdb.cursor
from pandas import DataFrame
from phoenixdb import connection

MAX_RETRIES = 3
CONNECTION = None


def get_wright_endpoint():
    """
    Returns WRIGHT_ENDPOINT from environment configuration
    If value not present, then returns localhost URL
    """
    endpoint = os.getenv("WRIGHT_ENDPOINT", "http://localhost:8080")
    return endpoint


def get_user_name():
    """
    Returns USER_NAME from environment configuration
    If value not present, then returns default value
    """
    user_name = os.environ.get("DP_USER", "test.user")
    return user_name


def get_password():
    """
    Returns ACCESS_TOKEN from environment configuration
    If value not present, then returns default value
    """
    password = os.environ.get("DP_PASSWORD", "")
    return password

def get_distributed_execution():
    """
    Returns DISTRIBUTED_EXECUTION from environment configuration
    If value not present, then returns default value
    """
    de = os.environ.get("DISTRIBUTED_EXECUTION", "true")
    return de

def get_partition_pruning():
    """
    Returns PARTITION_PRUNING from environment configuration
    If value not present, then returns default value
    """
    pp = os.environ.get("PARTITION_PRUNING", "true")
    return pp

def get_use_metastore_api():
    """
    Returns USE_NEW_METASTORE_API from environment configuration
    If value not present, then returns localhost URL
    """
    ms = os.getenv("USE_NEW_METASTORE_API", "false")
    return ms

def connect():
    """
    Read the wright endpoint from the environment variables
    Create the connection to Phoenix DB and return the connection
    :return:
    """
    args = {
                'serialization': 'protobuf',
                'fun': 'postgresql',
                'distributedExecution': get_distributed_execution(),
                'enablePartitionPruning': get_partition_pruning(),
                'dpUser': get_user_name(),
                'dpPassword': get_password(),
                'useNewMetastoreApi': get_use_metastore_api()
            }

    # Connect to the Wright Endpoint
    conn = None
    endpoint = get_wright_endpoint()
    try:
        conn = phoenixdb.connect(endpoint, max_retries=MAX_RETRIES, autocommit=True, **args)
        print("connection established\n")
    except Exception as e:
        print("Failed to connect to endpoint after {} retries.\n Exception: {}".format(MAX_RETRIES, e))

    return conn

def get_connection():
    """
    Gets a new connection if not exists else returns previous connection
    :return: CONNECTION
    """
    global CONNECTION
    if CONNECTION is None:
        CONNECTION = connect()
    return CONNECTION


def disconnect():
    """
    Disconnect the connection if already established
    :param conn:
    :return:
    """
    global CONNECTION
    if CONNECTION is not None:
        CONNECTION.close()
        CONNECTION=None
        print("connection terminated\n")


def execute_query(conn: connection, sql: str):
    """
    Execute the query and return dataframe in table format
    :param conn:
    :param sql:
    :return:
    """
    cursor = conn.cursor()
    start_time = time.time()
    cursor.execute(sql)
    if cursor.description is not None:
        column_names = []
        for column in cursor.description:
            column_names.append(column[0])
    df = DataFrame.from_records(data=cursor)
    df.rename(columns=dict(zip(df.columns, column_names)), inplace=True)
    exec_time = round(time.time() - start_time, 5)
    print(f"(rows, columns): {df.shape} | Execution Time: {exec_time} seconds")
    return df


def get_query_result(sql: str):
    """
    Create DB connection
    Execute the request
    Close the connection and return DataFrame
    :param sql:
    :return:
    """
    dp_connection = get_connection()
    df = execute_query(conn=dp_connection, sql=sql)
    return df
