import sqlglot
from sql_metadata import Parser
from sqlglot import exp


def replace_sub_queries(sql: str) -> str:
    """
    :param sql:
    :return: returns a single query by replacing the sub-queries
    """
    pass


def get_select_columns(sql: str):
    """
    Filter select columns from the query
    :param sql:
    :return: dict of select columns with column name as key and alias as value if any
    """
    columns = {}
    parsed = Parser(sql)
    all_columns = parsed.columns_dict
    if all_columns is not None and 'select' in all_columns.keys():
        select_columns = all_columns['select']
        aliases = parsed.columns_aliases
        for column in select_columns:
            if aliases is not None and column in aliases.values():
                key = [i for i in aliases if aliases[i] == column]
                columns[column] = key[0]
            else:
                columns[column] = ''
    return columns


def is_star(sql: str):
    """
    IF sql query to select all, then function returns true
    :param sql:
    :return:
    """
    star = sqlglot.parse_one(sql).find(exp.Star)
    if star is None:
        return False
    return True


def is_count_with_where(sql: str):
    """
    IF sql query to return count based on the where clause, then function returns true
    :param sql:
    :return:
    """
    where = sqlglot.parse_one(sql).find(exp.Where)
    count = sqlglot.parse_one(sql).find(exp.Count)
    if where is not None and count is not None:
        return True
    return False


def is_count_with_group(sql: str):
    """
    IF sql query is to return count with Group By, then function returns true
    :param sql:
    :return:
    """
    group = sqlglot.parse_one(sql).find(exp.Group)
    count = sqlglot.parse_one(sql).find(exp.Count)
    if group is not None and count is not None:
        return True
    return False


def is_group_by_without_count(sql: str):
    group = sqlglot.parse_one(sql).find(exp.Group)
    count = sqlglot.parse_one(sql).find(exp.Count)
    if group is not None and count is None:
        return True
    return False


def is_bar(sql: str) -> bool:
    """
    check for specific conditions to display data in bar format
    :param sql:
    :return: True if any condition is satisfied else False
    """
    return is_count_with_where(sql) or is_group_by_without_count(sql)


def is_pie(sql: str) -> bool:
    """
    check for specific conditions to display data in pie format
    :param sql:
    :return: True if any condition is satisfied else False
    """
    return is_count_with_group(sql)


def get_data_display_type(sql: str) -> str:
    """
    Based on query type, this function returns how to display the data in Jupyter Notebook
    :param sql:
    :return: string format datatype
    """
    if is_bar(sql):
        return "bar"
    elif is_pie(sql):
        return "pie"
    else:
        return "table"

# sql_query = "select * from testglue.dovertestdb.userdata where country='Russia'"
# sql_query = "select count(country) as Russia1 from testglue.dovertestdb.userdata where country='Russia'"
# sql_query = "select count(c1) from testglue.rkdatatest.int_13_col_20_rows group by c1"
# sql_query = "SELECT * FROM Users where Name='Test'" # table
# sql_query = "SELECT count(1), name from users group by name" # pie
# sql_query = "SELECT max(volume), name from users group by name" # bar
# sql_query = """
# SELECT max(volume) as volume, max(high) as high, max(low) as low, month(date) as date, name
# from users where name = 'Test' group by name, month(date), name Order By month(date)
# """  # bar -> Need to check how bar will display

# print(get_data_display_type("select count(c10) from testglue.rkdatatest.mix_all_datatypes_10000_rows group by c10"))

# print(get_select_columns("select country, count(country) as user_count from users group by country"))
