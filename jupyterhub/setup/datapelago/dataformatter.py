from ipywidgets import *
from ipywidgets import widgets
from pandas import DataFrame
from IPython.display import display

df: DataFrame = DataFrame()
x_column = None
y_column = None
supported_formats = ['Bar', 'Pie', 'Line', "BarH"]
x_value = None
y_value = None


def get_formats(dd):
    """
    Based on selected visual type, we will display axis and it's columns for dataframe plot
    :param dd:
    :return:
    """
    data_type = dd
    global df, x_column, y_column
    options = list(df.columns.values)
    all_options = list(["*"] + options)

    if data_type in supported_formats:
        x_column = widgets.Dropdown(
            options=options,
            value=None,
            description='x-column:',
            disabled=False,
        )

        y_column = widgets.Dropdown(
            options=all_options,
            value=None,
            description='y-column:',
            disabled=False,
        )
        return [x_column, y_column]

    else:
        return []


def dp_visualize_formats(df1):
    """
    Returns supported visualization formats to Notebook
    :param df1:
    :return:
    """
    dd = widgets.Dropdown(
        options=supported_formats,
        value=None,
        description='Visualization: ',
        disabled=False,
    )
    global df
    df = df1
    return dd


def on_change_x(change):
    """
    Returns new value selected in the x-column dropdown
    :param change:
    :return:
    """
    global x_value
    if change['type'] == 'change' and change['name'] == 'value':
        x_value = change['new']


def on_change_y(change):
    """
    Returns new value selected in the y-column dropdown
    :param change:
    :return:
    """
    global y_value
    if change['type'] == 'change' and change['name'] == 'value':
        y_value = change['new']


def display_visualization(dd: Dropdown):
    """
    Displays x and y column values
    Listens to X & Y column changes
    Updates x_value and y_value based on the selected column values
    :param dd: Widget Dropdown
    :return:
    """
    global x_value, y_value
    # Clear any existing values
    x_value = None
    y_value = None
    if dd is not None:
        x, y = get_formats(dd)
        display(x)
        display(y)
        x.observe(on_change_x)
        y.observe(on_change_y)


def draw(dd: Dropdown):
    """
    Draws the plot based on selected visualization type
    :param dd: Widget Dropdown
    :return: Returns drawn plot
    """
    if dd is None or dd.value is None:
        print("Select a visualization type! (And don't run the section cell)")
    elif x_value is None or y_value is None:
        print("Please select both x-column and y-column values.")
    else:
        return draw_with_value(str(dd.value).lower(), x_value, y_value)


def draw_with_value(kind, x_col, y_col):
    """
    Draw the plot based on the X & Y-axis columns and selected kind on the given dataframe
    :param kind:
    :param x_col:
    :param y_col:
    :return:
    """
    try:
        if y_col == "*":
            if kind.lower() == "bar" or kind.lower() == "barh":
                return df[x_col].value_counts().plot(x=x_col, kind=kind, stacked=True)
            elif kind.lower() == "pie":
                return df[x_col].value_counts().plot(kind=kind, y=x_col, subplots=True, autopct='%.2f',
                                                     shadow=True, radius=2)
            elif kind.lower() == "line":
                return df[x_col].value_counts().sort_index().plot(x=x_col, kind=kind, subplots=True)

        elif kind.lower() == "bar" or kind.lower() == "barh" or kind.lower() == "line":
            return df.plot(kind=kind, x=x_col, y=y_col, stacked=True)
        else:
            return df.groupby(x_col).sum(numeric_only=True).plot(kind=kind, y=y_col, autopct='%1.0f%%', radius=2)
    except Exception as e:
        return e.__str__()
