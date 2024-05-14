import pandas as pd
from IPython.core.magic import register_line_cell_magic
from ipywidgets import interact

from datapelago.base import get_result
from datapelago.dataformatter import dp_visualize_formats, display_visualization, draw
from datapelago.dpqueryexecutor import disconnect

# Set Options for Pandas
pd.set_option("display.max_rows", 500)
pd.set_option("display.max_columns", 100)
pd.set_option('display.float_format', str)


@register_line_cell_magic
def dpsql(line, cell=None):
    return get_result(line, cell)

@register_line_cell_magic
def close_connection(line, cell=None):
    disconnect()


if __name__ == '__main__':
    from IPython import get_ipython
    get_ipython().register_magic_function(dpsql, magic_kind='line')


def select_visualize_formats(df):
    dd = dp_visualize_formats(df)
    interact(display_visualization, dd=dd)
    return dd
