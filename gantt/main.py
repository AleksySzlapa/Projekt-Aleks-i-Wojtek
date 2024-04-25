import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# Dane dla wykresu Gantta
tasks = ['pisanie back \n endu(Wojtek)', 'pisanie frontendu\n(Aleks)', 'integracja frontendu \nz backendem(zespołowe)', 'bug testing(Aleks)']
start_dates = ['2024-04-25', '2024-04-25', '2024-05-13', '2024-05-16']
end_dates = ['2024-05-13', '2024-05-13', '2024-05-16', '2024-05-19']

# Konwersja dat na format matplotlib
start_dates = [mdates.datestr2num(date) for date in start_dates]
end_dates = [mdates.datestr2num(date) for date in end_dates]

# Utworzenie subplotu
fig, ax = plt.subplots()

# Ustawienie osi X jako daty
ax.xaxis_date()

# Ustawienie tytułu i etykiet osi
ax.set_title('Wykres Gantta')
ax.set_xlabel('Data')
ax.set_ylabel('Zadania')

# Dodanie słupków dla każdego zadania
for i, task in enumerate(tasks):
    ax.barh(task, end_dates[i] - start_dates[i], left=start_dates[i])

# Ustawienie formatu dat na osi X
ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))

# Pokaż wykres
plt.tight_layout()
plt.savefig('wykres_gantta.png')
plt.show()