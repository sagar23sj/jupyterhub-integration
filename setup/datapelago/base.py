from datapelago.dpqueryexecutor import get_query_result


def get_result(line, cell=None):
    """
    Entry point for all queries to execute
    :param line:
    :param cell:
    :return:
    """
    try:
        if cell is None:
            line = line.replace(";", "")
            return get_query_result(line)
        else:
            cell = cell.replace(";", "")
            return get_query_result(cell)
    except Exception as e:
        return str(e)
