"""
File to contain TCP tahoe stuff
"""

def csv_split(line: str, delim: str, quote:str) -> list[str]:
    """
    Take in a string (line of csv file) and split at each delimitter.
    If inside of the quote char, do not split
    """
    res = []
    inside = 0
    curr = ""
    # iterate through the line of text
    for x in line:
        # check for quote char
        if x == quote:
            # toggle whether or not you are inside quotes
            inside ^= 1
            inside &= 1
        elif x == delim:
            if inside:
                # dont do anything special if inside quotes
                pass
            else:
                # if we hit a delim while outside quotes
                res.append(curr.strip(quote))
                curr = ""
                continue
        curr += x

    # add the final value
    res.append(curr.strip(quote))

    return res



def read_csv(filename: str) -> list[list[str]]:
    """
    Take in a filename and return a list of lists of entries in that csv file
    """
    # open and read the file
    try: 
        with open(filename, 'r') as f:
            lines = f.readlines()
    except:
        print(f"Failed to open file: '{filename}'")

    # number of column headers
    headers = 0

    # separate each line of the file at commas
    for i in range(len(lines)):
        # split the line at the commas
        line = csv_split(lines[i].strip(), ",", '"')

        # if this is the first line (column headers)
        if i == 0:
            # the number of elements we expect
            headers = len(line)

        print(line)



read_csv("output.csv")




