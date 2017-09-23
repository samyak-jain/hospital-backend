import csv
import sqlite3

datafile = open("set1.csv", "rt", encoding="latin-1")
connection = sqlite3.connect("data.db")

old_dataset = csv.reader(datafile)

dataset = []

for row in old_dataset:
    row_elements = []
    for i in range(9):
        row_elements.append(row[i])
    row_elements.append(row[11])
    dataset.append(row_elements)

columns = ["ProviderID", "HospitalName", "Address", "City", "State", "ZIP", "Country", "Phone", "Condition", "Score"]
query = "insert into set1({0}) values ({1})"
query = query.format(','.join(columns), ','.join('?' * len(columns)))
cursor = connection.cursor()
for data in dataset:
    cursor.execute(query, data)
connection.commit()


datafile.close()