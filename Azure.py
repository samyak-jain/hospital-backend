import sqlite3

def get_hospitalList():
    conn = sqlite3.connect('data.db')
    c = conn.cursor()
    c.execute("select * from hospitalList Limit 200")
    ListData = list()
    for row in c.fetchall():
        ListData.append(row)
    conn.close()
    return ListData

def get_details(ListData):
    conn = sqlite3.connect('data.db')
    c = conn.cursor()
    prov_id = []
    for i in ListData:
        prov_id.append(str(i[0]))
    counter = 0
    Details = []
    for ele in prov_id:
        Details.append(list())
        c.execute("select * from hospitalDetails where ProviderID=" + ele)
        for row in c.fetchall():
            Details[counter].append(row)
        counter += 1
    conn.close()
    return Details